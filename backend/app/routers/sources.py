from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone
import csv, io, re, xml.etree.ElementTree as ET
from ..database import get_db
from ..models import SourceConfig, User, GenericIOC, IntelEvent
from ..deps import get_current_user
from ..collectors import COLLECTOR_REGISTRY, SOURCE_METADATA
from ..services.ingestion import run_ingestion_for_user
from ..services.enrichment import compute_severity

router = APIRouter(prefix="/api/sources", tags=["sources"])


class SourceCreate(BaseModel):
    name: str
    source_type: str
    api_url: str | None = None
    api_key: str | None = None
    verify_ssl: bool = True


class CustomConnectorCreate(BaseModel):
    name: str
    description: str | None = "Custom Threat Intelligence Connector"
    category: str = "feed"
    use_case: str = "Infrastructure & Attack Surface Management"
    integration_type: str = "Connectors"
    deployment_type: str = "Container"
    api_url: str | None = None
    api_key: str | None = None
    verify_ssl: bool = True


class IngestFilePayload(BaseModel):
    filename: str
    content: str
    format: str | None = None # "csv" or "xml"


class SourceOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    name: str
    source_type: str
    api_url: str | None
    verify_ssl: bool
    is_active: bool
    last_sync: datetime | None
    created_at: datetime


TYPE_MAP = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip-address": "ip",
    "domain": "domain", "hostname": "domain", "fqdn": "domain",
    "url": "url", "uri": "url", "link": "url", "endpoint": "url",
    "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash", "sha-256": "hash", "file_hash": "hash",
    "email": "email", "mail": "email"
}


def detect_ioc_type(val: str) -> str:
    val = val.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", val):
        return "ip"
    if val.startswith("http://") or val.startswith("https://"):
        return "url"
    if re.match(r"^[a-fA-F0-9]{32}$", val) or re.match(r"^[a-fA-F0-9]{40}$", val) or re.match(r"^[a-fA-F0-9]{64}$", val):
        return "hash"
    if "@" in val and "/" not in val:
        return "email"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?$", val):
        return "domain"
    return "url" if "/" in val else "domain"


def parse_csv_iocs(text: str):
    results = []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return results

    reader = csv.DictReader(io.StringIO(text))
    has_valid_headers = False
    if reader.fieldnames:
        lower_fields = [f.lower() for f in reader.fieldnames if f]
        if any(f in lower_fields for f in ["value", "indicator", "observable", "ioc", "ip", "url", "domain", "hash"]):
            has_valid_headers = True

    if has_valid_headers:
        for row in reader:
            val = None
            ioc_type = None
            threat = None
            malware = None
            severity = None

            for k, v in row.items():
                if not k or not v:
                    continue
                k_low = k.strip().lower()
                v_str = str(v).strip()
                if k_low in ("value", "indicator", "observable", "ioc"):
                    val = v_str
                elif k_low in ("type", "ioc_type", "observable_type", "kind"):
                    ioc_type = TYPE_MAP.get(v_str.lower(), v_str.lower())
                elif k_low in ("threat", "threat_type", "threat_level", "category"):
                    threat = v_str
                elif k_low in ("malware", "family", "malware_family", "payload"):
                    malware = v_str
                elif k_low in ("severity", "score", "confidence"):
                    try:
                        severity = float(v_str)
                    except:
                        pass
                elif not val and k_low in ("ip", "url", "domain", "hash"):
                    val = v_str
                    ioc_type = k_low

            if val:
                if not ioc_type:
                    ioc_type = detect_ioc_type(val)
                results.append({
                    "value": val,
                    "type": ioc_type,
                    "threat": threat or "malware_download",
                    "malware": malware or "Generic Malicious Artifact",
                    "severity": severity
                })
    else:
        raw_reader = csv.reader(io.StringIO(text))
        for row in raw_reader:
            if not row:
                continue
            val = row[0].strip()
            if val.lower() in ("value", "indicator", "observable", "ioc", "type", "#"):
                continue
            ioc_type = detect_ioc_type(val)
            threat = row[1].strip() if len(row) > 1 else "malware_download"
            malware = row[2].strip() if len(row) > 2 else "Imported Artifact"
            results.append({
                "value": val,
                "type": ioc_type,
                "threat": threat,
                "malware": malware,
                "severity": None
            })
    return results


def parse_xml_iocs(text: str):
    results = []
    try:
        root = ET.fromstring(text)
    except Exception as e:
        raise ValueError(f"Invalid XML syntax: {e}")

    ioc_tags = {"ioc", "indicator", "observable", "item", "record", "entry", "indicatoritem"}
    found_nodes = False

    for elem in root.iter():
        tag_low = elem.tag.split("}")[-1].lower()
        if tag_low in ioc_tags:
            found_nodes = True
            val = None
            ioc_type = elem.attrib.get("type") or elem.attrib.get("ioc_type")
            threat = elem.attrib.get("threat") or elem.attrib.get("threat_type")
            malware = elem.attrib.get("malware") or elem.attrib.get("family")
            severity = None
            if elem.attrib.get("severity"):
                try: severity = float(elem.attrib.get("severity"))
                except: pass

            if elem.text and elem.text.strip():
                val = elem.text.strip()

            for child in elem:
                c_tag = child.tag.split("}")[-1].lower()
                c_text = child.text.strip() if child.text else ""
                if c_tag in ("value", "indicator", "observable", "content", "address", "ip", "url", "domain", "hash") and c_text:
                    val = c_text
                    if not ioc_type and c_tag in ("ip", "url", "domain", "hash"):
                        ioc_type = c_tag
                elif c_tag in ("type", "ioc_type", "kind") and c_text:
                    ioc_type = TYPE_MAP.get(c_text.lower(), c_text.lower())
                elif c_tag in ("threat", "threat_type", "category") and c_text:
                    threat = c_text
                elif c_tag in ("malware", "family", "payload") and c_text:
                    malware = c_text
                elif c_tag in ("severity", "score") and c_text:
                    try: severity = float(c_text)
                    except: pass

            if val:
                if not ioc_type:
                    ioc_type = detect_ioc_type(val)
                results.append({
                    "value": val,
                    "type": ioc_type,
                    "threat": threat or "malware_download",
                    "malware": malware or "XML Artifact",
                    "severity": severity
                })

    if not found_nodes:
        for elem in root.iter():
            if elem.text and elem.text.strip():
                t = elem.text.strip()
                if 6 < len(t) < 500:
                    ioc_type = None
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t):
                        ioc_type = "ip"
                    elif t.startswith("http://") or t.startswith("https://"):
                        ioc_type = "url"
                    elif re.match(r"^[a-fA-F0-9]{32,64}$", t):
                        ioc_type = "hash"
                    if ioc_type:
                        results.append({
                            "value": t,
                            "type": ioc_type,
                            "threat": "malware_download",
                            "malware": "XML Observable",
                            "severity": 8.0
                        })
    return results


@router.get("/available")
def available_sources():
    return SOURCE_METADATA


@router.get("", response_model=list[SourceOut])
def list_sources(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(SourceConfig).filter_by(user_id=user.id).all()


@router.post("", response_model=SourceOut)
def add_source(payload: SourceCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if payload.source_type not in SOURCE_METADATA:
        raise HTTPException(400, f"unsupported source_type: {payload.source_type}")
    meta = SOURCE_METADATA[payload.source_type]
    if meta.get("requires_url", False) and not payload.api_url:
        raise HTTPException(400, "api_url required")
    if meta.get("requires_key", False) and not payload.api_key:
        raise HTTPException(400, "api_key required")
    src = SourceConfig(user_id=user.id, **payload.model_dump())
    db.add(src)
    db.commit()
    db.refresh(src)
    return src


@router.delete("/{source_id}", status_code=204)
def delete_source(source_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    src = db.query(SourceConfig).filter_by(id=source_id, user_id=user.id).first()
    if not src:
        raise HTTPException(404, "not found")
    db.delete(src)
    db.commit()
    return None


@router.post("/sync")
async def sync_all(user: User = Depends(get_current_user)):
    return await run_ingestion_for_user(user.id)


@router.post("/{source_id}/sync")
async def sync_one(source_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    src = db.query(SourceConfig).filter_by(id=source_id, user_id=user.id).first()
    if not src:
        raise HTTPException(404, "not found")
    others = db.query(SourceConfig).filter(
        SourceConfig.user_id == user.id, SourceConfig.id != source_id
    ).all()
    saved = [(o, o.is_active) for o in others]
    for o, _ in saved:
        o.is_active = False
    db.commit()
    try:
        result = await run_ingestion_for_user(user.id)
    finally:
        for o, val in saved:
            o.is_active = val
        db.commit()
    return result


@router.post("/custom", response_model=SourceOut)
def create_custom_connector(
    payload: CustomConnectorCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    type_slug = re.sub(r"[^a-zA-Z0-9_]", "_", payload.name.lower())[:20]
    custom_type_id = f"custom_{type_slug}_{int(datetime.utcnow().timestamp())}"

    SOURCE_METADATA[custom_type_id] = {
        "display_name": payload.name,
        "description": payload.description or "User-defined custom connector",
        "category": payload.category,
        "use_case": payload.use_case,
        "integration_type": payload.integration_type,
        "deployment_type": payload.deployment_type,
        "solution_category": "Threat Intelligence",
        "license_type": "Custom",
        "version": "V.1.0.0",
        "author": "Custom Connector",
        "tags": [payload.integration_type, "Custom Feed"],
        "requires_url": bool(payload.api_url),
        "requires_key": bool(payload.api_key),
        "requires_ssl_toggle": True,
        "status": "Active",
        "icon": "csv"
    }

    src = SourceConfig(
        user_id=user.id,
        name=payload.name,
        source_type=custom_type_id,
        api_url=payload.api_url,
        api_key=payload.api_key,
        verify_ssl=payload.verify_ssl,
        is_active=True
    )
    db.add(src)
    db.commit()
    db.refresh(src)
    return src


@router.post("/ingest-file")
async def ingest_iocs_from_file(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    filename = "manual_ingest.csv"
    content = ""
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "filename"):
            filename = uploaded_file.filename or filename
            raw_bytes = await uploaded_file.read()
            try:
                content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content = raw_bytes.decode("latin-1", errors="ignore")
        elif form.get("content"):
            content = str(form.get("content"))
            filename = str(form.get("filename") or filename)
    else:
        try:
            body = await request.json()
            filename = body.get("filename") or filename
            content = body.get("content") or ""
        except Exception:
            raw_bytes = await request.body()
            content = raw_bytes.decode("utf-8", errors="ignore")

    if not content or not content.strip():
        raise HTTPException(400, "No file or content provided for ingestion")

    is_xml = filename.lower().endswith(".xml") or content.strip().startswith("<")
    parsed_iocs = []
    if is_xml:
        try:
            parsed_iocs = parse_xml_iocs(content)
        except Exception as ex:
            raise HTTPException(400, f"Error parsing XML file: {ex}")
    else:
        try:
            parsed_iocs = parse_csv_iocs(content)
        except Exception as ex:
            raise HTTPException(400, f"Error parsing CSV file: {ex}")

    if not parsed_iocs:
        raise HTTPException(400, "No valid IOCs found in the provided file. Ensure CSV has observable values or XML has indicator nodes.")

    upload_src = db.query(SourceConfig).filter_by(user_id=user.id, source_type="csv_feed").first()
    if not upload_src:
        upload_src = SourceConfig(
            user_id=user.id,
            name="File Ingestion (CSV / XML)",
            source_type="csv_feed",
            is_active=True,
            verify_ssl=True
        )
        db.add(upload_src)
        db.commit()
        db.refresh(upload_src)

    event = IntelEvent(
        source_id=upload_src.id,
        external_id=f"file-ingest-{int(datetime.utcnow().timestamp())}",
        title=f"File Ingestion: {filename}",
        description=f"Batch ingestion of {len(parsed_iocs)} observables from {filename}",
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        organization="Manual File Upload",
        threat_level="2",
        tags="manual_upload,file_ingest"
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Fetch existing IOCs for this source to deduplicate gracefully
    existing_records = db.query(GenericIOC.ioc_type, GenericIOC.value).filter(
        GenericIOC.source_id == upload_src.id
    ).all()
    existing_set = {(r[0], r[1]) for r in existing_records}
    seen_in_batch = set()

    inserted_count = 0
    type_counts = {}
    sample_iocs = []

    for item in parsed_iocs:
        ioc_val = item["value"][:500]
        ioc_type = item["type"]
        key = (ioc_type, ioc_val)
        if key in existing_set or key in seen_in_batch:
            continue
        seen_in_batch.add(key)

        threat_type = item.get("threat") or "malware_download"
        malware = item.get("malware")

        class TempIOC:
            pass
        t = TempIOC()
        t.threat_type = threat_type
        t.malware = malware

        sev = item.get("severity")
        if sev is None:
            sev = compute_severity(t)

        ioc = GenericIOC(
            source_id=upload_src.id,
            event_id=event.id,
            ioc_type=ioc_type,
            value=ioc_val,
            severity=sev,
            threat_type=threat_type,
            malware=malware,
            first_seen=datetime.now(timezone.utc)
        )
        db.add(ioc)
        inserted_count += 1
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        if len(sample_iocs) < 5:
            sample_iocs.append({
                "type": ioc_type,
                "value": ioc_val,
                "threat": threat_type,
                "malware": malware,
                "severity": sev
            })

    upload_src.last_sync = datetime.now(timezone.utc)
    db.commit()

    return {
        "success": True,
        "filename": filename,
        "message": f"Successfully ingested {inserted_count} new IOCs from {filename}.",
        "ingested_count": inserted_count,
        "total_records_processed": len(parsed_iocs),
        "by_type": type_counts,
        "sample_iocs": sample_iocs
    }