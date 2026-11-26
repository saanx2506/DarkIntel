import json
import logging
from datetime import datetime
import httpx
from sqlalchemy.orm import Session
from ..models import GalaxyCluster, Adversary, GalaxySyncState

logger = logging.getLogger("galaxy_sync")

GITHUB_REPO = "MISP/misp-galaxy"
GITHUB_BRANCH = "main"
GITHUB_COMMITS_API = f"https://api.github.com/repos/{GITHUB_REPO}/commits/{GITHUB_BRANCH}"
RAW_BASE_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/clusters"

# Priority clusters covering adversaries, threat actors, intrusion sets, and ransomware
CLUSTER_CONFIGS = [
    {
        "filename": "threat-actor.json",
        "cluster_type": "threat-actor",
        "display_name": "Threat Actors",
    },
    {
        "filename": "microsoft-activity-group.json",
        "cluster_type": "microsoft-activity-group",
        "display_name": "Microsoft Activity Groups",
    },
    {
        "filename": "mitre-enterprise-attack-intrusion-set.json",
        "cluster_type": "mitre-intrusion-set",
        "display_name": "MITRE Intrusion Sets",
    },
    {
        "filename": "ransomware.json",
        "cluster_type": "ransomware",
        "display_name": "Ransomware Operations",
    },
    {
        "filename": "tool.json",
        "cluster_type": "tool",
        "display_name": "Adversary Tools",
    },
]


async def fetch_latest_commit_info() -> dict:
    headers = {"User-Agent": "DarkIntel-GalaxySync/1.0", "Accept": "application/vnd.github.v3+json"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(GITHUB_COMMITS_API, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            commit_obj = data.get("commit", {})
            committer = commit_obj.get("committer", {}) or commit_obj.get("author", {})
            return {
                "sha": data.get("sha"),
                "date": committer.get("date"),
                "message": commit_obj.get("message", "").split("\n")[0],
            }
        else:
            logger.warning(f"Failed to fetch GitHub commits API: {resp.status_code}")
            return {"sha": None, "date": None, "message": None}


def get_or_create_sync_state(db: Session) -> GalaxySyncState:
    state = db.query(GalaxySyncState).filter_by(repo=GITHUB_REPO, branch=GITHUB_BRANCH).first()
    if not state:
        state = GalaxySyncState(
            repo=GITHUB_REPO,
            branch=GITHUB_BRANCH,
            status="idle",
        )
        db.add(state)
        db.commit()
        db.refresh(state)
    return state


async def sync_galaxy_from_github(db: Session, force: bool = False) -> dict:
    state = get_or_create_sync_state(db)
    state.is_syncing = True
    state.status = "checking_github"
    state.error = None
    db.commit()

    try:
        commit_info = await fetch_latest_commit_info()
        latest_sha = commit_info.get("sha")

        # If not forced and commit has not changed, skip re-download
        if not force and latest_sha and state.last_commit_sha == latest_sha:
            adversary_count = db.query(Adversary).count()
            if adversary_count > 0:
                state.is_syncing = False
                state.status = "idle"
                state.last_synced_at = datetime.utcnow()
                db.commit()
                return {
                    "status": "up_to_date",
                    "commit_sha": latest_sha,
                    "commit_date": commit_info.get("date"),
                    "commit_message": commit_info.get("message"),
                    "total_adversaries": adversary_count,
                    "updated": False,
                }

        state.status = "downloading_clusters"
        db.commit()

        total_synced = 0
        clusters_synced = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            for cfg in CLUSTER_CONFIGS:
                filename = cfg["filename"]
                cluster_type = cfg["cluster_type"]
                display_name = cfg["display_name"]
                url = f"{RAW_BASE_URL}/{filename}"

                try:
                    res = await client.get(url, headers={"User-Agent": "DarkIntel-GalaxySync/1.0"})
                    if res.status_code != 200:
                        logger.error(f"Failed to fetch {url}: {res.status_code}")
                        continue

                    cluster_data = res.json()
                    values = cluster_data.get("values", [])

                    # Find or create GalaxyCluster
                    cluster_obj = db.query(GalaxyCluster).filter_by(cluster_type=cluster_type).first()
                    if not cluster_obj:
                        cluster_obj = GalaxyCluster(
                            cluster_type=cluster_type,
                            name=cluster_data.get("name") or display_name,
                            description=cluster_data.get("description"),
                            version=str(cluster_data.get("version", "")),
                            source_url=url,
                        )
                        db.add(cluster_obj)
                        db.flush()
                    else:
                        cluster_obj.name = cluster_data.get("name") or display_name
                        cluster_obj.description = cluster_data.get("description")
                        cluster_obj.version = str(cluster_data.get("version", ""))
                        cluster_obj.source_url = url

                    # Map existing adversaries by uuid to avoid duplicates
                    existing_by_uuid = {
                        adv.uuid: adv
                        for adv in db.query(Adversary).filter_by(cluster_id=cluster_obj.id).all()
                    }

                    for val in values:
                        uuid_val = val.get("uuid")
                        if not uuid_val:
                            continue

                        name_val = val.get("value") or "Unknown Adversary"
                        desc_val = val.get("description")
                        meta = val.get("meta") or {}

                        # Extract metadata fields
                        country_raw = meta.get("country") or meta.get("cfr-suspected-state-sponsor")
                        country_val = None
                        if country_raw:
                            if isinstance(country_raw, list):
                                country_val = ", ".join(str(x) for x in country_raw)[:16]
                            else:
                                country_val = str(country_raw)[:16]

                        state_sponsor_raw = meta.get("cfr-suspected-state-sponsor") or meta.get("state-sponsor")
                        state_sponsor = None
                        if state_sponsor_raw:
                            if isinstance(state_sponsor_raw, list):
                                state_sponsor = ", ".join(str(x) for x in state_sponsor_raw)[:128]
                            else:
                                state_sponsor = str(state_sponsor_raw)[:128]

                        synonyms_list = meta.get("synonyms") or []
                        if isinstance(synonyms_list, str):
                            synonyms_list = [synonyms_list]

                        target_list = meta.get("cfr-target-category") or meta.get("target-category") or []
                        if isinstance(target_list, str):
                            target_list = [target_list]

                        incident_raw = meta.get("cfr-type-of-incident") or meta.get("type-of-incident")
                        incident_type = None
                        if incident_raw:
                            if isinstance(incident_raw, list):
                                incident_type = ", ".join(str(x) for x in incident_raw)[:128]
                            else:
                                incident_type = str(incident_raw)[:128]

                        refs_list = meta.get("refs") or []
                        if isinstance(refs_list, str):
                            refs_list = [refs_list]

                        meta_json_str = json.dumps(meta)
                        synonyms_str = json.dumps(synonyms_list)
                        target_str = json.dumps(target_list)
                        refs_str = json.dumps(refs_list)

                        if uuid_val in existing_by_uuid:
                            adv = existing_by_uuid[uuid_val]
                            adv.name = name_val
                            adv.description = desc_val
                            adv.country = country_val
                            adv.state_sponsor = state_sponsor
                            adv.synonyms = synonyms_str
                            adv.target_category = target_str
                            adv.incident_type = incident_type
                            adv.refs = refs_str
                            adv.meta_json = meta_json_str
                            adv.updated_at = datetime.utcnow()
                        else:
                            adv = Adversary(
                                cluster_id=cluster_obj.id,
                                uuid=uuid_val,
                                name=name_val,
                                description=desc_val,
                                country=country_val,
                                state_sponsor=state_sponsor,
                                synonyms=synonyms_str,
                                target_category=target_str,
                                incident_type=incident_type,
                                refs=refs_str,
                                meta_json=meta_json_str,
                            )
                            db.add(adv)

                        total_synced += 1

                    cluster_obj.elements_count = len(values)
                    cluster_obj.last_synced = datetime.utcnow()
                    clusters_synced += 1
                    db.flush()

                except Exception as ex:
                    logger.exception(f"Error syncing cluster {filename}: {ex}")

        # Update sync state
        if latest_sha:
            state.last_commit_sha = latest_sha
            state.last_commit_date = commit_info.get("date")
            state.last_commit_message = commit_info.get("message")
        state.last_synced_at = datetime.utcnow()
        state.is_syncing = False
        state.status = "idle"
        db.commit()

        total_adversaries = db.query(Adversary).count()
        return {
            "status": "success",
            "commit_sha": state.last_commit_sha,
            "commit_date": state.last_commit_date,
            "commit_message": state.last_commit_message,
            "clusters_synced": clusters_synced,
            "total_adversaries": total_adversaries,
            "updated": True,
        }

    except Exception as e:
        logger.exception(f"Galaxy sync failed: {e}")
        state.is_syncing = False
        state.status = "error"
        state.error = str(e)
        db.commit()
        return {
            "status": "error",
            "error": str(e),
            "commit_sha": state.last_commit_sha,
        }
