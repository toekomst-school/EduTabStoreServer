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
QUARANTINE_DIR = "/data/quarantine"
CATEGORIES_FILE = os.path.join(CONFIG_DIR, "categories.json")


def load_categories():
    """Load predefined categories from config file"""
    if not os.path.exists(CATEGORIES_FILE):
        return []
    try:
        with open(CATEGORIES_FILE, "r") as f:
            data = json.load(f)
            return data.get("categories", [])
    except Exception:
        return []


def save_categories(categories):
    """Save predefined categories to config file"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CATEGORIES_FILE, "w") as f:
        json.dump({"categories": categories}, f, indent=2)


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


def validate_apk_for_fdroid(apk_path):
    """
    Pre-validate APK to ensure it won't crash fdroid update.
    Tests the same parsing that fdroid uses (androguard).
    Returns (is_valid, error_message)
    """
    try:
        from androguard.core.apk import APK

        print(f"[validate] Testing APK: {os.path.basename(apk_path)}")

        # Load APK (this parses AndroidManifest.xml)
        apk = APK(apk_path)

        # Get package info (basic validation)
        package = apk.get_package()
        if not package:
            return False, "Could not extract package name from APK"

        version_code = apk.get_androidversion_code()
        version_name = apk.get_androidversion_name()

        print(f"[validate] Package: {package}, version: {version_name} ({version_code})")

        # Try to get resources - this is what usually crashes fdroid
        try:
            resources = apk.get_android_resources()
            if resources:
                # Try to actually parse the resources (triggers ResParserError if broken)
                _ = resources.get_packages_names()
                print(f"[validate] Resources parsed successfully")
        except Exception as res_error:
            error_msg = str(res_error)
            # Check for known androguard parsing errors
            if "res0 must be" in error_msg or "res1 must be" in error_msg or "reserved must be" in error_msg:
                return False, f"APK has incompatible resources.arsc format (androguard cannot parse it): {error_msg}"
            elif "KeyError" in error_msg and "resources.arsc" in error_msg:
                return False, "APK is missing resources.arsc or it cannot be read"
            else:
                # Log but don't fail for other resource errors - some APKs work despite this
                print(f"[validate] Warning: Resource parsing issue (non-fatal): {error_msg}")

        # Verify APK signature using apksigner (if available)
        try:
            sig_result = subprocess.run(
                ["apksigner", "verify", "--print-certs", apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if sig_result.returncode != 0:
                # Check if it's a critical signature error
                if "DOES NOT VERIFY" in sig_result.stdout or "ERROR" in sig_result.stderr:
                    return False, f"APK signature verification failed: {sig_result.stderr or sig_result.stdout}"
                print(f"[validate] Signature check warning: {sig_result.stderr}")
            else:
                print(f"[validate] Signature verified")
        except FileNotFoundError:
            print("[validate] apksigner not available, skipping signature check")
        except Exception as sig_error:
            print(f"[validate] Signature check error (non-fatal): {sig_error}")

        print(f"[validate] APK validation passed: {package}")
        return True, None

    except ImportError:
        # Androguard not installed - fall back to basic aapt check
        print("[validate] Androguard not available, using basic validation")
        package = get_package_from_apk(apk_path)
        if package:
            return True, None
        return False, "Could not read APK package info"

    except Exception as e:
        error_msg = str(e)
        print(f"[validate] APK validation failed: {error_msg}")

        # Provide helpful error messages for common issues
        if "is not a valid zip file" in error_msg.lower() or "bad zip file" in error_msg.lower():
            return False, "File is not a valid APK (corrupted or not a zip file)"
        elif "AndroidManifest.xml" in error_msg:
            return False, f"APK has invalid AndroidManifest.xml: {error_msg}"

        return False, f"APK validation failed: {error_msg}"


def quarantine_apk(apk_path, reason):
    """Move a failed APK to quarantine directory with error info"""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

    filename = os.path.basename(apk_path)
    timestamp = int(time.time())
    quarantine_name = f"{timestamp}_{filename}"
    quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

    # Move the APK
    shutil.move(apk_path, quarantine_path)

    # Write error info
    info_path = os.path.join(QUARANTINE_DIR, f"{quarantine_name}.txt")
    with open(info_path, "w") as f:
        f.write(f"Original filename: {filename}\n")
        f.write(f"Quarantined at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Reason: {reason}\n")

    print(f"[quarantine] Moved {filename} to quarantine: {reason}")
    return quarantine_path


def check_virustotal_safety(apk_path, max_malicious=0, max_suspicious=2):
    """
    Pre-check APK against VirusTotal before accepting it.
    Returns (is_safe, result_dict)

    result_dict contains:
    - status: 'safe', 'unsafe', 'unknown', 'error', 'skipped'
    - detections: dict with malicious/suspicious counts (if known)
    - message: human-readable explanation
    """
    if not VIRUSTOTAL_API_KEY:
        return True, {
            "status": "skipped",
            "message": "VirusTotal API key not configured, skipping safety check"
        }

    try:
        sha256 = get_file_sha256(apk_path)
        print(f"[virustotal] Checking SHA256: {sha256}")

        # Check if file is already known to VirusTotal
        vt_report, vt_error = virustotal_get_file_report(sha256)

        if vt_error and "not found" in vt_error.lower():
            # File not in VirusTotal database - it's unknown
            print(f"[virustotal] File not in database (unknown)")
            return True, {
                "status": "unknown",
                "sha256": sha256,
                "message": "File not yet scanned by VirusTotal. Will be submitted for scanning."
            }

        if vt_error:
            print(f"[virustotal] API error: {vt_error}")
            return True, {
                "status": "error",
                "message": f"VirusTotal check failed: {vt_error}"
            }

        if not vt_report:
            return True, {
                "status": "unknown",
                "sha256": sha256,
                "message": "Could not get VirusTotal report"
            }

        # Extract detection stats
        stats = extract_virustotal_stats(vt_report)
        if not stats:
            return True, {
                "status": "unknown",
                "sha256": sha256,
                "message": "Could not parse VirusTotal results"
            }

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = stats.get("total", 0)

        print(f"[virustotal] Results: {malicious} malicious, {suspicious} suspicious out of {total} engines")

        # Check against thresholds
        if malicious > max_malicious:
            return False, {
                "status": "unsafe",
                "sha256": sha256,
                "detections": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total
                },
                "message": f"APK flagged as malicious by {malicious} antivirus engines (threshold: {max_malicious})"
            }

        if suspicious > max_suspicious:
            return False, {
                "status": "unsafe",
                "sha256": sha256,
                "detections": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total
                },
                "message": f"APK flagged as suspicious by {suspicious} antivirus engines (threshold: {max_suspicious})"
            }

        # File is safe
        return True, {
            "status": "safe",
            "sha256": sha256,
            "detections": {
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total
            },
            "message": f"APK passed VirusTotal check ({malicious} malicious, {suspicious} suspicious)"
        }

    except Exception as e:
        print(f"[virustotal] Check error: {e}")
        return True, {
            "status": "error",
            "message": f"VirusTotal check failed: {str(e)}"
        }


def run_fdroid_update():
    """Run fdroid update command"""
    try:
        print("[fdroid] Running fdroid update --create-metadata --verbose")
        result = subprocess.run(
            ["fdroid", "update", "--create-metadata", "--verbose"],
            cwd="/data/repo",
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout + result.stderr

        if result.returncode != 0:
            print(f"[fdroid] Update FAILED (exit code {result.returncode})")
            print(f"[fdroid] Output: {output}")
            return False, output

        # Verify index was actually created
        index_v1 = os.path.exists("/data/repo/repo/index-v1.jar")
        index_v2 = os.path.exists("/data/repo/repo/index-v2.json")

        if not index_v1 and not index_v2:
            print("[fdroid] WARNING: Update succeeded but no index files found!")
            return False, output + "\nWARNING: No index files generated"

        print(f"[fdroid] Update successful (index-v1: {index_v1}, index-v2: {index_v2})")
        return True, output
    except subprocess.TimeoutExpired:
        print("[fdroid] Update TIMEOUT after 5 minutes")
        return False, "fdroid update timed out after 5 minutes"
    except Exception as e:
        print(f"[fdroid] Update ERROR: {e}")
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
        try:
            import yaml
            with open(yml_path, "r") as f:
                yml_data = yaml.safe_load(f) or {}
            # Add yml fields to metadata
            if "Categories" in yml_data:
                info["metadata"]["categories"] = yml_data["Categories"]
            if "AuthorName" in yml_data:
                info["metadata"]["authorName"] = yml_data["AuthorName"]
            if "AuthorEmail" in yml_data:
                info["metadata"]["authorEmail"] = yml_data["AuthorEmail"]
            if "License" in yml_data:
                info["metadata"]["license"] = yml_data["License"]
            if "WebSite" in yml_data:
                info["metadata"]["webSite"] = yml_data["WebSite"]
            if "SourceCode" in yml_data:
                info["metadata"]["sourceCode"] = yml_data["SourceCode"]
        except Exception:
            pass

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

    # Pre-validate APK to ensure it won't crash fdroid update
    is_valid, validation_error = validate_apk_for_fdroid(temp_path)
    if not is_valid:
        quarantine_apk(temp_path, validation_error)
        return jsonify({
            "error": "APK validation failed",
            "details": validation_error,
            "quarantined": True,
            "hint": "The APK may be built with incompatible tools. Try a different version or build variant."
        }), 400

    # Pre-check VirusTotal for known malware (if enabled)
    if scan_virustotal:
        is_safe, vt_result = check_virustotal_safety(temp_path)
        if not is_safe:
            quarantine_apk(temp_path, f"VirusTotal: {vt_result.get('message', 'Unsafe')}")
            return jsonify({
                "error": "APK flagged as unsafe by VirusTotal",
                "details": vt_result.get("message"),
                "detections": vt_result.get("detections"),
                "sha256": vt_result.get("sha256"),
                "quarantined": True,
                "hint": "This APK has been flagged by antivirus engines. Do not install it."
            }), 400

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

    # Save VirusTotal results (already checked above, now save for record)
    if scan_virustotal and VIRUSTOTAL_API_KEY:
        vt_report, vt_error = virustotal_get_file_report(sha256)
        if vt_report:
            save_virustotal_result(package, sha256, vt_report)
            stats = extract_virustotal_stats(vt_report)
            response_data["virustotal"] = {
                "status": "completed",
                "sha256": sha256,
                "stats": stats,
                "message": "File passed VirusTotal check"
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
        # F-Droid requires Categories to be a YAML list
        cats = data["categories"]
        if isinstance(cats, str):
            # Single category as string -> convert to list
            cats = [cats] if cats else []
        elif not isinstance(cats, list):
            # Other iterable -> convert to list
            cats = list(cats) if hasattr(cats, '__iter__') else [str(cats)]
        # Filter out empty strings
        cats = [c for c in cats if c]
        yml_fields["Categories"] = cats
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


@app.route("/api/categories", methods=["GET"])
@require_api_key
def api_list_categories():
    """List all predefined categories"""
    categories = load_categories()
    return jsonify({"categories": categories})


@app.route("/api/categories", methods=["POST"])
@require_api_key
def api_add_category():
    """Add a new predefined category"""
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Category name required"}), 400

    name = data["name"].strip()
    if not name:
        return jsonify({"error": "Category name cannot be empty"}), 400

    categories = load_categories()

    if name in categories:
        return jsonify({"error": "Category already exists"}), 409

    categories.append(name)
    categories.sort()
    save_categories(categories)

    return jsonify({"success": True, "category": name, "categories": categories})


@app.route("/api/categories/<name>", methods=["DELETE"])
@require_api_key
def api_delete_category(name):
    """Delete a predefined category"""
    categories = load_categories()

    if name not in categories:
        return jsonify({"error": "Category not found"}), 404

    categories.remove(name)
    save_categories(categories)

    return jsonify({"success": True, "deleted": name, "categories": categories})


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


def download_apk_with_apkeep(package_name, source="apk-pure"):
    """
    Download APK using apkeep CLI tool.
    Sources: apk-pure, google-play, f-droid, huawei-app-gallery
    Returns (filepath, error_message)
    """
    try:
        import subprocess
        import glob

        os.makedirs(DOWNLOADS_DIR, exist_ok=True)

        # Build apkeep command
        cmd = ["apkeep", "-a", package_name, "-d", source, DOWNLOADS_DIR]

        # Run apkeep
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            return None, f"apkeep ({source}) failed: {error_msg}"

        # Find the downloaded APK (apkeep names files as package_version.apk)
        pattern = os.path.join(DOWNLOADS_DIR, f"{package_name}*.apk")
        apk_files = glob.glob(pattern)

        if not apk_files:
            return None, f"apkeep completed but no APK found for {package_name}"

        # Return the most recently modified file
        latest_apk = max(apk_files, key=os.path.getmtime)
        return latest_apk, None

    except subprocess.TimeoutExpired:
        return None, f"apkeep ({source}) timed out after 5 minutes"
    except Exception as e:
        return None, f"apkeep ({source}) error: {str(e)}"


def download_from_google_play(package_name):
    """
    Download APK from Google Play Store using apkeep.
    Returns (filepath, error_message)
    """
    return download_apk_with_apkeep(package_name, "google-play")


def download_from_apkpure(package_name):
    """
    Download APK from APKPure using apkeep.
    Returns (filepath, error_message)
    """
    return download_apk_with_apkeep(package_name, "apk-pure")


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

    # Pre-validate APK to ensure it won't crash fdroid update
    is_valid, validation_error = validate_apk_for_fdroid(apk_path)
    if not is_valid:
        quarantine_apk(apk_path, validation_error)
        return {
            "success": False,
            "error": "APK validation failed",
            "details": validation_error,
            "quarantined": True,
            "hint": "The APK may be built with incompatible tools. Try a different version or build variant."
        }

    # Pre-check VirusTotal for known malware
    if scan_virustotal:
        is_safe, vt_result = check_virustotal_safety(apk_path)
        if not is_safe:
            quarantine_apk(apk_path, f"VirusTotal: {vt_result.get('message', 'Unsafe')}")
            return {
                "success": False,
                "error": "APK flagged as unsafe by VirusTotal",
                "details": vt_result.get("message"),
                "detections": vt_result.get("detections"),
                "sha256": vt_result.get("sha256"),
                "quarantined": True,
                "hint": "This APK has been flagged by antivirus engines. Do not install it."
            }

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

    # Save VirusTotal results for record
    if scan_virustotal and VIRUSTOTAL_API_KEY:
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
