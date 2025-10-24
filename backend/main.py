from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
import time
import tempfile
from dotenv import load_dotenv
import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException
import pyclamd
load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# VirusTotal API key and helper function remain unchanged
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def get_analysis_report(analysis_id):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    resp = requests.get(url, headers=headers)
    print("analysi response :", resp.text)
    return resp.json()

@app.post("/scan/virustotal")
async def scan_file(file: UploadFile = File(...)):
    try:
        file_data = await file.read()
        files = {"file": (file.filename, file_data, "application/octet-stream")}
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        upload_resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files
        )
        print("upload response :", upload_resp.text)
        upload_data = upload_resp.json()

        if "data" not in upload_data:
            return {"error": upload_data.get("error", upload_data)}

        analysis_id = upload_data["data"]["id"]

        MAX_POLL_TIME = 60  # seconds
        poll_interval = 15   # seconds between polls
        max_attempts = MAX_POLL_TIME // poll_interval

        for attempt in range(max_attempts):
            report = get_analysis_report(analysis_id)
            attrs = report.get("data", {}).get("attributes", {})
            status = attrs.get("status")

            print(f"Attempt {attempt + 1}: status={status}")

            if status == "completed":
                break
            elif status in ("queued", "in_progress"):
                time.sleep(poll_interval)
            else:
                # Unexpected status; break out early
                break
        else:
            # Timeout expired without completion
            return {
                "verdict": "⏳ Analysis pending",
                "message": "The file scan is still queued on VirusTotal. Please try again later.",
                "raw_report": report
            }

        stats = attrs.get("stats", {})
        verdict = "🚨 Malicious!" if stats.get("malicious", 0) > 0 else "✅ Safe"

        results = []
        for engine_name, engine_data in attrs.get("results", {}).items():
            results.append({
                "engine": engine_data.get("engine_name", engine_name),
                "category": engine_data.get("category"),
                "result": engine_data.get("result")
            })

        file_info = report.get("meta", {}).get("file_info", {})

        return {
            "provider": "virustotal",
            "verdict": verdict,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timeout": stats.get("timeout", 0),
                "type_unsupported": stats.get("type-unsupported", 0),
                "failure": stats.get("failure", 0)
            },
            "results": results,
            "file_info": file_info,
            "raw_report": report
        }

    except Exception as e:
        return {"error": str(e)}

# Cloudmersive scan setup using their official Python client
CLOUDMERSIVE_API_KEY = os.getenv("CLOUDMERSIVE_API_KEY")
cloudmersive_config = cloudmersive_virus_api_client.Configuration()
cloudmersive_config.api_key['Apikey'] = CLOUDMERSIVE_API_KEY
cloudmersive_client = cloudmersive_virus_api_client.ScanApi(
    cloudmersive_virus_api_client.ApiClient(cloudmersive_config)
)

@app.post("/scan/cloudmersive")
async def scan_cloudmersive(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            temp_file.write(contents)
            temp_file.close()

            api_response = cloudmersive_client.scan_file(temp_file.name)
            print("Cloudmersive API response:", api_response)

            # Determine verdict based on clean_result and found_viruses
            if api_response.found_viruses is None:
                # Treat None as False - no viruses found
                verdict = "✅ Safe"
                malicious = 0
            elif api_response.found_viruses:
                verdict = "🚨 Malicious!"
                malicious = 1
            else:
                verdict = "✅ Safe"
                malicious = 0

            stats = {
                "malicious": malicious,
                "suspicious": 0,
                "undetected": 1 if malicious == 0 else 0,
                "harmless": 0,
                "timeout": 0,
                "type_unsupported": 0,
                "failure": 0
            }

            # No detailed results available in response, so empty list
            results = []

            file_info = {
                "size": getattr(api_response, "input_file_size", None),
                "md5": None,
                "sha1": None,
                "sha256": None
            }

            raw_report = api_response.to_dict() if hasattr(api_response, "to_dict") else {}

            return {
                "provider": "cloudmersive",
                "verdict": verdict,
                "stats": stats,
                "results": results,
                "file_info": file_info,
                "raw_report": raw_report
            }

        finally:
            os.unlink(temp_file.name)
    except ApiException as e:
        return {"error": f"Cloudmersive API error: {e}"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/scan/clamav")
async def scan_clamav(file: UploadFile = File(...)):
    contents = await file.read()

    # Connect to ClamAV daemon over TCP
    cd = pyclamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)
    if not cd.ping():
        return {"error": "Cannot connect to ClamAV daemon"}

    # Scan file bytes directly
    scan_result = cd.scan_stream(contents)

    if scan_result is None:
        verdict = "✅ Safe"
        stats = {"malicious": 0, "suspicious": 0, "undetected": 1,
                 "harmless": 0, "timeout": 0, "type_unsupported": 0, "failure": 0}
        results = []
    else:
        verdict = "🚨 Malicious!"
        stats = {"malicious": 1, "suspicious": 0, "undetected": 0,
                 "harmless": 0, "timeout": 0, "type_unsupported": 0, "failure": 0}
        results = [{"engine": "ClamAV", "category": "malware", "result": list(scan_result.values())[0][0]}]

    return {
        "provider": "clamav",
        "verdict": verdict,
        "stats": stats,
        "results": results,
        "file_info": {"size": len(contents)},
        "raw_report": scan_result if scan_result else {}
    }
