"""
EdutabStore Admin API - Flask REST API for managing F-Droid repository
"""

import os
import subprocess
import glob
import shutil
import hashlib
import json
import time
import requests
from functools import wraps
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
REPO_DIR = "/data/repo/repo"
METADATA_DIR = "/data/repo/metadata"
CONFIG_DIR = "/data/config"
VIRUSTOTAL_DIR = "/data/virustotal"
ALLOWED_EXTENSIONS = {"apk"}
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg"}
API_KEY = os.environ.get("ADMIN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY:
            return jsonify({"error": "API key not configured on server"}), 500

        provided_key = request.headers.get("X-API-Key")
        if not provided_key or provided_key != API_KEY:
            return jsonify({"error": "Invalid or missing API key"}), 401

        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename, extensions):
    """Check if file has allowed extension"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in extensions


def get_package_from_apk(apk_path):
    """Extract package name from APK using aapt"""
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        for line in result.stdout.split("\n"):
            if line.startswith("package:"):
                # Parse: package: name='com.example.app' versionCode='1' ...
                parts = line.split("'")
                if len(parts) >= 2:
                    return parts[1]
    except Exception:
        pass
    return None


def run_fdroid_update():
    """Run fdroid update command"""
    try:
        result = subprocess.run(
            ["fdroid", "update", "--create-metadata"],
            cwd="/data/repo",
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def get_file_sha256(filepath):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def virustotal_upload_file(filepath):
    """Upload file to VirusTotal for scanning"""
    if not VIRUSTOTAL_API_KEY:
        return None, "VirusTotal API key not configured"

    try:
        # First, get upload URL for large files
        file_size = os.path.getsize(filepath)

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        if file_size > 32 * 1024 * 1024:  # > 32MB
            # Get special upload URL for large files
            url_response = requests.get(
                "https://www.virustotal.com/api/v3/files/upload_url",
                headers=headers,
                timeout=30
            )
            if url_response.status_code != 200:
                return None, f"Failed to get upload URL: {url_response.text}"
            upload_url = url_response.json()["data"]
        else:
            upload_url = "https://www.virustotal.com/api/v3/files"

        # Upload the file
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f, "application/vnd.android.package-archive")}
            response = requests.post(
                upload_url,
                headers=headers,
                files=files,
                timeout=300
            )

        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            return analysis_id, None
        else:
            return None, f"Upload failed: {response.status_code} - {response.text}"

    except Exception as e:
        return None, str(e)


def virustotal_get_analysis(analysis_id):
    """Get analysis results from VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return None, "VirusTotal API key not configured"

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"Failed to get analysis: {response.status_code}"

    except Exception as e:
        return None, str(e)


def virustotal_get_file_report(sha256):
    """Get existing report for a file by SHA256"""
    if not VIRUSTOTAL_API_KEY:
        return None, "VirusTotal API key not configured"

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            return response.json(), None
        elif response.status_code == 404:
            return None, "File not found in VirusTotal database"
        else:
            return None, f"Failed to get report: {response.status_code}"

    except Exception as e:
        return None, str(e)


def save_virustotal_result(package, sha256, result):
    """Save VirusTotal scan result to metadata"""
    os.makedirs(VIRUSTOTAL_DIR, exist_ok=True)
    filepath = os.path.join(VIRUSTOTAL_DIR, f"{package}_{sha256[:16]}.json")
    with open(filepath, "w") as f:
        json.dump({
            "package": package,
            "sha256": sha256,
            "timestamp": time.time(),
            "result": result
        }, f, indent=2)
    return filepath


def get_virustotal_result(package):
    """Get saved VirusTotal results for a package"""
    if not os.path.exists(VIRUSTOTAL_DIR):
        return []

    results = []
    for filename in os.listdir(VIRUSTOTAL_DIR):
        if filename.startswith(f"{package}_") and filename.endswith(".json"):
            filepath = os.path.join(VIRUSTOTAL_DIR, filename)
            with open(filepath, "r") as f:
                results.append(json.load(f))

    return sorted(results, key=lambda x: x.get("timestamp", 0), reverse=True)


def extract_virustotal_stats(vt_result):
    """Extract key stats from VirusTotal result"""
    if not vt_result:
        return None

    data = vt_result.get("data", {})
    attributes = data.get("attributes", {})

    # Handle analysis response
    if "stats" in attributes:
        stats = attributes["stats"]
        return {
            "status": attributes.get("status", "unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values())
        }

    # Handle file report response
    if "last_analysis_stats" in attributes:
        stats = attributes["last_analysis_stats"]
        return {
            "status": "completed",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values()),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0)
        }

    return None


def list_apps():
    """Get list of all apps in repository"""
    apps = []

    # Get APK files
    apk_files = glob.glob(os.path.join(REPO_DIR, "*.apk"))
    packages = set()

    for apk_path in apk_files:
        package = get_package_from_apk(apk_path)
        if package:
            packages.add(package)

    # Also check metadata directory
    if os.path.exists(METADATA_DIR):
        for entry in os.listdir(METADATA_DIR):
            metadata_path = os.path.join(METADATA_DIR, entry)
            if os.path.isdir(metadata_path):
                packages.add(entry)

    for package in sorted(packages):
        app_info = get_app_info(package)
        if app_info:
            apps.append(app_info)

    return apps


def get_app_info(package):
    """Get detailed info about an app"""
    metadata_dir = os.path.join(METADATA_DIR, package)

    # Find APK file
    apk_files = glob.glob(os.path.join(REPO_DIR, f"{package}_*.apk"))
    if not apk_files:
        apk_files = glob.glob(os.path.join(REPO_DIR, "*.apk"))
        apk_files = [f for f in apk_files if get_package_from_apk(f) == package]

    if not apk_files and not os.path.exists(metadata_dir):
        return None

    info = {
        "package": package,
        "apk_count": len(apk_files),
        "metadata": {}
    }

    # Read metadata files
    if os.path.exists(metadata_dir):
        locale_dir = os.path.join(metadata_dir, "en-US")
        if not os.path.exists(locale_dir):
            # Try to find any locale
            locales = [d for d in os.listdir(metadata_dir)
                      if os.path.isdir(os.path.join(metadata_dir, d))]
            if locales:
                locale_dir = os.path.join(metadata_dir, locales[0])

        if os.path.exists(locale_dir):
            # Read text metadata
            for field in ["title.txt", "summary.txt", "full_description.txt"]:
                field_path = os.path.join(locale_dir, field)
                if os.path.exists(field_path):
                    with open(field_path, "r") as f:
                        key = field.replace(".txt", "").replace("full_", "")
                        info["metadata"][key] = f.read().strip()

            # List screenshots
            images_dir = os.path.join(locale_dir, "images", "phoneScreenshots")
            if os.path.exists(images_dir):
                info["screenshots"] = os.listdir(images_dir)

    # Read yml metadata if exists
    yml_path = os.path.join(METADATA_DIR, f"{package}.yml")
    if os.path.exists(yml_path):
        info["has_yml_metadata"] = True

    # Get VirusTotal scan results
    vt_results = get_virustotal_result(package)
    if vt_results:
        latest = vt_results[0]
        stats = extract_virustotal_stats(latest.get("result"))
        info["virustotal"] = {
            "sha256": latest.get("sha256"),
            "scanned_at": latest.get("timestamp"),
            "stats": stats
        }

    return info


@app.route("/api/apps", methods=["GET"])
@require_api_key
def api_list_apps():
    """List all apps in repository"""
    apps = list_apps()
    return jsonify({"apps": apps})


@app.route("/api/apps", methods=["POST"])
@require_api_key
def api_upload_apk():
    """Upload a new APK file"""
    if "apk" not in request.files:
        return jsonify({"error": "No APK file provided"}), 400

    file = request.files["apk"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
        return jsonify({"error": "File must be an APK"}), 400

    # Check if we should scan with VirusTotal
    scan_virustotal = request.form.get("scan", "true").lower() == "true"

    # Save APK to temp location first
    filename = secure_filename(file.filename)
    temp_path = os.path.join("/tmp", filename)
    file.save(temp_path)

    # Get package name
    package = get_package_from_apk(temp_path)
    if not package:
        os.remove(temp_path)
        return jsonify({"error": "Could not read package info from APK"}), 400

    # Calculate SHA256 for VirusTotal
    sha256 = get_file_sha256(temp_path)

    # Move to repo
    dest_path = os.path.join(REPO_DIR, filename)
    shutil.move(temp_path, dest_path)

    # Run fdroid update
    success, output = run_fdroid_update()

    response_data = {
        "success": True,
        "package": package,
        "filename": filename,
        "sha256": sha256,
        "fdroid_update": success,
        "output": output if not success else "Repository updated"
    }

    # Trigger VirusTotal scan
    if scan_virustotal and VIRUSTOTAL_API_KEY:
        # First check if already scanned
        vt_report, vt_error = virustotal_get_file_report(sha256)
        if vt_report:
            # Already scanned, save the result
            save_virustotal_result(package, sha256, vt_report)
            stats = extract_virustotal_stats(vt_report)
            response_data["virustotal"] = {
                "status": "completed",
                "sha256": sha256,
                "stats": stats,
                "message": "File already in VirusTotal database"
            }
        else:
            # Need to upload for scanning
            analysis_id, upload_error = virustotal_upload_file(dest_path)
            if analysis_id:
                response_data["virustotal"] = {
                    "status": "pending",
                    "analysis_id": analysis_id,
                    "sha256": sha256,
                    "message": "Scan initiated, check status with /api/apps/{package}/virustotal"
                }
            else:
                response_data["virustotal"] = {
                    "status": "error",
                    "error": upload_error
                }
    elif not VIRUSTOTAL_API_KEY:
        response_data["virustotal"] = {
            "status": "skipped",
            "message": "VIRUSTOTAL_API_KEY not configured"
        }

    return jsonify(response_data)


@app.route("/api/apps/<package>", methods=["GET"])
@require_api_key
def api_get_app(package):
    """Get details for a specific app"""
    info = get_app_info(package)
    if not info:
        return jsonify({"error": "App not found"}), 404
    return jsonify(info)


@app.route("/api/apps/<package>", methods=["DELETE"])
@require_api_key
def api_delete_app(package):
    """Delete an app and all its files"""
    deleted_files = []

    # Delete APK files
    apk_files = glob.glob(os.path.join(REPO_DIR, f"{package}_*.apk"))
    if not apk_files:
        apk_files = glob.glob(os.path.join(REPO_DIR, "*.apk"))
        apk_files = [f for f in apk_files if get_package_from_apk(f) == package]

    for apk_path in apk_files:
        os.remove(apk_path)
        deleted_files.append(os.path.basename(apk_path))

    # Delete metadata directory
    metadata_dir = os.path.join(METADATA_DIR, package)
    if os.path.exists(metadata_dir):
        shutil.rmtree(metadata_dir)
        deleted_files.append(f"metadata/{package}/")

    # Delete yml file if exists
    yml_path = os.path.join(METADATA_DIR, f"{package}.yml")
    if os.path.exists(yml_path):
        os.remove(yml_path)
        deleted_files.append(f"metadata/{package}.yml")

    if not deleted_files:
        return jsonify({"error": "App not found"}), 404

    # Run fdroid update
    success, output = run_fdroid_update()

    return jsonify({
        "success": True,
        "deleted": deleted_files,
        "fdroid_update": success
    })


@app.route("/api/apps/<package>/metadata", methods=["PUT"])
@require_api_key
def api_update_metadata(package):
    """Update app metadata"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    # Verify app exists
    info = get_app_info(package)
    if not info:
        return jsonify({"error": "App not found"}), 404

    # Create metadata directory structure
    locale_dir = os.path.join(METADATA_DIR, package, "en-US")
    os.makedirs(locale_dir, exist_ok=True)

    # Map JSON fields to F-Droid metadata files
    field_mapping = {
        "name": "title.txt",
        "title": "title.txt",
        "summary": "summary.txt",
        "description": "full_description.txt"
    }

    updated_fields = []

    for json_field, filename in field_mapping.items():
        if json_field in data:
            filepath = os.path.join(locale_dir, filename)
            with open(filepath, "w") as f:
                f.write(str(data[json_field]))
            updated_fields.append(json_field)

    # Handle categories and other yml fields
    yml_fields = {}
    if "categories" in data:
        yml_fields["Categories"] = data["categories"]
        updated_fields.append("categories")
    if "authorName" in data:
        yml_fields["AuthorName"] = data["authorName"]
        updated_fields.append("authorName")
    if "authorEmail" in data:
        yml_fields["AuthorEmail"] = data["authorEmail"]
        updated_fields.append("authorEmail")
    if "license" in data:
        yml_fields["License"] = data["license"]
        updated_fields.append("license")
    if "webSite" in data:
        yml_fields["WebSite"] = data["webSite"]
        updated_fields.append("webSite")
    if "sourceCode" in data:
        yml_fields["SourceCode"] = data["sourceCode"]
        updated_fields.append("sourceCode")

    # Write yml file if we have yml fields
    if yml_fields:
        yml_path = os.path.join(METADATA_DIR, f"{package}.yml")
        existing_yml = {}

        # Read existing yml if present
        if os.path.exists(yml_path):
            import yaml
            with open(yml_path, "r") as f:
                existing_yml = yaml.safe_load(f) or {}

        # Update with new fields
        existing_yml.update(yml_fields)

        import yaml
        with open(yml_path, "w") as f:
            yaml.dump(existing_yml, f, default_flow_style=False)

    # Run fdroid update
    success, output = run_fdroid_update()

    return jsonify({
        "success": True,
        "updated_fields": updated_fields,
        "fdroid_update": success
    })


@app.route("/api/apps/<package>/screenshots", methods=["POST"])
@require_api_key
def api_upload_screenshot(package):
    """Upload screenshot for an app"""
    if "screenshot" not in request.files:
        return jsonify({"error": "No screenshot file provided"}), 400

    file = request.files["screenshot"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
        return jsonify({"error": "File must be PNG or JPG"}), 400

    # Verify app exists
    info = get_app_info(package)
    if not info:
        return jsonify({"error": "App not found"}), 404

    # Create screenshots directory
    screenshots_dir = os.path.join(
        METADATA_DIR, package, "en-US", "images", "phoneScreenshots"
    )
    os.makedirs(screenshots_dir, exist_ok=True)

    # Generate filename (sequential numbering)
    existing = os.listdir(screenshots_dir)
    ext = file.filename.rsplit(".", 1)[1].lower()
    index = len(existing) + 1
    filename = f"{index}.{ext}"

    # Save file
    filepath = os.path.join(screenshots_dir, filename)
    file.save(filepath)

    # Run fdroid update
    success, output = run_fdroid_update()

    return jsonify({
        "success": True,
        "filename": filename,
        "path": f"metadata/{package}/en-US/images/phoneScreenshots/{filename}",
        "fdroid_update": success
    })


@app.route("/api/apps/<package>/screenshots/<filename>", methods=["DELETE"])
@require_api_key
def api_delete_screenshot(package, filename):
    """Delete a screenshot for an app"""
    # Verify app exists
    info = get_app_info(package)
    if not info:
        return jsonify({"error": "App not found"}), 404

    # Sanitize filename to prevent directory traversal
    filename = secure_filename(filename)

    # Build path to screenshot
    screenshot_path = os.path.join(
        METADATA_DIR, package, "en-US", "images", "phoneScreenshots", filename
    )

    if not os.path.exists(screenshot_path):
        return jsonify({"error": "Screenshot not found"}), 404

    # Delete the file
    os.remove(screenshot_path)

    # Run fdroid update
    success, output = run_fdroid_update()

    return jsonify({
        "success": True,
        "deleted": filename,
        "fdroid_update": success
    })


@app.route("/api/update", methods=["POST"])
@require_api_key
def api_force_update():
    """Force repository update"""
    success, output = run_fdroid_update()

    return jsonify({
        "success": success,
        "output": output
    })


@app.route("/api/apps/<package>/virustotal", methods=["GET"])
@require_api_key
def api_get_virustotal(package):
    """Get VirusTotal scan results for an app"""
    info = get_app_info(package)
    if not info:
        return jsonify({"error": "App not found"}), 404

    vt_results = get_virustotal_result(package)
    if not vt_results:
        return jsonify({
            "package": package,
            "scans": [],
            "message": "No VirusTotal scans found for this package"
        })

    scans = []
    for result in vt_results:
        stats = extract_virustotal_stats(result.get("result"))
        scans.append({
            "sha256": result.get("sha256"),
            "scanned_at": result.get("timestamp"),
            "stats": stats
        })

    return jsonify({
        "package": package,
        "scans": scans
    })


@app.route("/api/apps/<package>/virustotal", methods=["POST"])
@require_api_key
def api_scan_virustotal(package):
    """Trigger VirusTotal scan for an app"""
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "VIRUSTOTAL_API_KEY not configured"}), 500

    info = get_app_info(package)
    if not info:
        return jsonify({"error": "App not found"}), 404

    # Find APK file
    apk_files = glob.glob(os.path.join(REPO_DIR, f"{package}_*.apk"))
    if not apk_files:
        apk_files = glob.glob(os.path.join(REPO_DIR, "*.apk"))
        apk_files = [f for f in apk_files if get_package_from_apk(f) == package]

    if not apk_files:
        return jsonify({"error": "No APK file found for this package"}), 404

    # Use the latest APK (sorted by modification time)
    apk_path = max(apk_files, key=os.path.getmtime)
    sha256 = get_file_sha256(apk_path)

    # Check if already scanned
    force_rescan = request.args.get("force", "false").lower() == "true"

    if not force_rescan:
        vt_report, _ = virustotal_get_file_report(sha256)
        if vt_report:
            save_virustotal_result(package, sha256, vt_report)
            stats = extract_virustotal_stats(vt_report)
            return jsonify({
                "status": "completed",
                "package": package,
                "sha256": sha256,
                "stats": stats,
                "message": "File already in VirusTotal database"
            })

    # Upload for scanning
    analysis_id, upload_error = virustotal_upload_file(apk_path)
    if analysis_id:
        return jsonify({
            "status": "pending",
            "package": package,
            "analysis_id": analysis_id,
            "sha256": sha256,
            "message": "Scan initiated, poll this endpoint to check status"
        })
    else:
        return jsonify({
            "status": "error",
            "error": upload_error
        }), 500


@app.route("/api/virustotal/analysis/<analysis_id>", methods=["GET"])
@require_api_key
def api_check_virustotal_analysis(analysis_id):
    """Check status of a VirusTotal analysis"""
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "VIRUSTOTAL_API_KEY not configured"}), 500

    result, error = virustotal_get_analysis(analysis_id)
    if error:
        return jsonify({"error": error}), 500

    stats = extract_virustotal_stats(result)
    status = result.get("data", {}).get("attributes", {}).get("status", "unknown")

    response = {
        "analysis_id": analysis_id,
        "status": status,
        "stats": stats
    }

    # If completed, try to save results
    if status == "completed":
        # Get the file hash from the analysis
        meta = result.get("meta", {})
        file_info = meta.get("file_info", {})
        sha256 = file_info.get("sha256")
        if sha256:
            # Try to get full file report
            full_report, _ = virustotal_get_file_report(sha256)
            if full_report:
                response["full_report_available"] = True

    return jsonify(response)


@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint (no auth required)"""
    return jsonify({"status": "ok"})


# =============================================================================
# Google Play / APKPure Import
# =============================================================================

GOOGLE_PLAY_EMAIL = os.environ.get("GOOGLE_PLAY_EMAIL", "")
GOOGLE_PLAY_PASSWORD = os.environ.get("GOOGLE_PLAY_PASSWORD", "")
DOWNLOADS_DIR = "/data/downloads"


def download_from_google_play(package_name):
    """
    Download APK from Google Play Store using gpapi.
    Returns (filepath, error_message)
    """
    if not GOOGLE_PLAY_EMAIL or not GOOGLE_PLAY_PASSWORD:
        return None, "Google Play credentials not configured"

    try:
        from gpapi.googleplay import GooglePlayAPI

        os.makedirs(DOWNLOADS_DIR, exist_ok=True)

        # Initialize API
        api = GooglePlayAPI(locale="en_US", timezone="UTC")

        # Login
        api.login(GOOGLE_PLAY_EMAIL, GOOGLE_PLAY_PASSWORD)

        # Get app details first
        details = api.details(package_name)
        if not details:
            return None, f"App {package_name} not found on Google Play"

        version_code = details.get("versionCode")
        offer_type = details.get("offer", [{}])[0].get("offerType", 1)

        # Download APK
        download = api.download(package_name, versionCode=version_code, offerType=offer_type)

        filename = f"{package_name}_{version_code}.apk"
        filepath = os.path.join(DOWNLOADS_DIR, filename)

        with open(filepath, "wb") as f:
            for chunk in download.get("file", {}).get("data", b""):
                f.write(chunk)

        return filepath, None

    except Exception as e:
        return None, f"Google Play download failed: {str(e)}"


def download_from_apkpure(package_name):
    """
    Download APK from APKPure as fallback.
    Returns (filepath, error_message)
    """
    try:
        from bs4 import BeautifulSoup

        os.makedirs(DOWNLOADS_DIR, exist_ok=True)

        # Get app page
        app_url = f"https://apkpure.com/search?q={package_name}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # Search for the app
        response = requests.get(app_url, headers=headers, timeout=30)
        if response.status_code != 200:
            return None, f"APKPure search failed: {response.status_code}"

        soup = BeautifulSoup(response.text, "html.parser")

        # Find the app link
        app_link = None
        for link in soup.select("a.first-info"):
            href = link.get("href", "")
            if package_name in href:
                app_link = href
                break

        if not app_link:
            # Try alternative selector
            for link in soup.select("a[href*='" + package_name + "']"):
                href = link.get("href", "")
                if "/download" not in href and package_name in href:
                    app_link = href
                    break

        if not app_link:
            return None, f"App {package_name} not found on APKPure"

        # Get the download page
        if not app_link.startswith("http"):
            app_link = f"https://apkpure.com{app_link}"

        download_page_url = f"{app_link}/download"
        response = requests.get(download_page_url, headers=headers, timeout=30)
        if response.status_code != 200:
            return None, f"APKPure download page failed: {response.status_code}"

        soup = BeautifulSoup(response.text, "html.parser")

        # Find download link
        download_link = None
        for link in soup.select("a[href*='.apk']"):
            href = link.get("href", "")
            if ".apk" in href and "download" in href.lower():
                download_link = href
                break

        # Alternative: look for download button
        if not download_link:
            download_btn = soup.select_one("a.download-start-btn")
            if download_btn:
                download_link = download_btn.get("href")

        if not download_link:
            return None, "Could not find APK download link on APKPure"

        # Download the APK
        if not download_link.startswith("http"):
            download_link = f"https://apkpure.com{download_link}"

        apk_response = requests.get(download_link, headers=headers, timeout=300, stream=True)
        if apk_response.status_code != 200:
            return None, f"APK download failed: {apk_response.status_code}"

        # Generate filename
        timestamp = int(time.time())
        filename = f"{package_name}_{timestamp}.apk"
        filepath = os.path.join(DOWNLOADS_DIR, filename)

        with open(filepath, "wb") as f:
            for chunk in apk_response.iter_content(chunk_size=8192):
                f.write(chunk)

        return filepath, None

    except Exception as e:
        return None, f"APKPure download failed: {str(e)}"


def import_apk_to_repo(apk_path, scan_virustotal=True):
    """
    Import a downloaded APK into the F-Droid repository.
    Returns response dict with status.
    """
    # Get package name from APK
    package = get_package_from_apk(apk_path)
    if not package:
        os.remove(apk_path)
        return {"success": False, "error": "Could not read package info from APK"}

    # Calculate SHA256
    sha256 = get_file_sha256(apk_path)

    # Move to repo
    filename = os.path.basename(apk_path)
    dest_path = os.path.join(REPO_DIR, filename)
    shutil.move(apk_path, dest_path)

    # Run fdroid update
    fdroid_success, fdroid_output = run_fdroid_update()

    response_data = {
        "success": True,
        "package": package,
        "filename": filename,
        "sha256": sha256,
        "fdroid_update": fdroid_success,
        "output": fdroid_output if not fdroid_success else "Repository updated"
    }

    # VirusTotal scan
    if scan_virustotal and VIRUSTOTAL_API_KEY:
        # Check if already scanned
        vt_report, _ = virustotal_get_file_report(sha256)
        if vt_report:
            save_virustotal_result(package, sha256, vt_report)
            stats = extract_virustotal_stats(vt_report)
            response_data["virustotal"] = {
                "status": "completed",
                "sha256": sha256,
                "stats": stats,
                "message": "File already in VirusTotal database"
            }
        else:
            # Upload for scanning
            analysis_id, upload_error = virustotal_upload_file(dest_path)
            if analysis_id:
                response_data["virustotal"] = {
                    "status": "pending",
                    "analysis_id": analysis_id,
                    "sha256": sha256,
                    "message": "Scan initiated, check status with /api/apps/{package}/virustotal"
                }
            else:
                response_data["virustotal"] = {
                    "status": "error",
                    "error": upload_error
                }
    elif not VIRUSTOTAL_API_KEY:
        response_data["virustotal"] = {
            "status": "skipped",
            "message": "VIRUSTOTAL_API_KEY not configured"
        }

    return response_data


@app.route("/api/import/playstore", methods=["POST"])
@require_api_key
def api_import_from_playstore():
    """
    Import an app from Google Play Store (with APKPure fallback).
    Automatically scans with VirusTotal.

    Request body:
    {
        "package": "com.example.app",
        "scan": true  // optional, default true
    }
    """
    data = request.get_json()
    if not data or "package" not in data:
        return jsonify({"error": "Package name required"}), 400

    package_name = data["package"].strip()
    scan_virustotal = data.get("scan", True)

    # Validate package name format
    if not package_name or "." not in package_name:
        return jsonify({"error": "Invalid package name format"}), 400

    # Try Google Play first
    filepath, gplay_error = download_from_google_play(package_name)

    source = "google_play"
    fallback_error = None

    # Fallback to APKPure
    if not filepath:
        fallback_error = gplay_error
        filepath, apkpure_error = download_from_apkpure(package_name)
        source = "apkpure"

        if not filepath:
            return jsonify({
                "error": "Download failed from all sources",
                "google_play_error": gplay_error,
                "apkpure_error": apkpure_error
            }), 500

    # Import APK to repository
    result = import_apk_to_repo(filepath, scan_virustotal)
    result["source"] = source
    if fallback_error:
        result["primary_source_error"] = fallback_error

    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 500


@app.route("/api/import/search", methods=["GET"])
@require_api_key
def api_search_playstore():
    """
    Search for apps on Google Play Store.

    Query params:
    - q: search query (required)
    - limit: max results (optional, default 10)
    """
    query = request.args.get("q", "").strip()
    limit = int(request.args.get("limit", 10))

    if not query:
        return jsonify({"error": "Search query required"}), 400

    if not GOOGLE_PLAY_EMAIL or not GOOGLE_PLAY_PASSWORD:
        return jsonify({"error": "Google Play credentials not configured"}), 500

    try:
        from gpapi.googleplay import GooglePlayAPI

        api = GooglePlayAPI(locale="en_US", timezone="UTC")
        api.login(GOOGLE_PLAY_EMAIL, GOOGLE_PLAY_PASSWORD)

        results = api.search(query, nb_result=limit)

        apps = []
        for app in results:
            doc = app.get("docV2", app)
            apps.append({
                "package": doc.get("docid", ""),
                "title": doc.get("title", ""),
                "creator": doc.get("creator", ""),
                "icon": doc.get("image", [{}])[0].get("imageUrl", "") if doc.get("image") else ""
            })

        return jsonify({"query": query, "results": apps})

    except Exception as e:
        return jsonify({"error": f"Search failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
