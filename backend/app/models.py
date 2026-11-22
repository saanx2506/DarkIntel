from datetime import datetime
from sqlalchemy import (
    String, DateTime, Float, Integer, Text, Boolean,
    ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str | None] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    sources: Mapped[list["SourceConfig"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class SourceConfig(Base):
    __tablename__ = "source_configs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    api_url: Mapped[str | None] = mapped_column(String(256))
    api_key: Mapped[str | None] = mapped_column(String(256))
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="sources")
    events: Mapped[list["IntelEvent"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["GenericIOC"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class IntelEvent(Base):
    __tablename__ = "intel_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source_configs.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    date: Mapped[str | None] = mapped_column(String(32))
    organization: Mapped[str | None] = mapped_column(String(128))
    threat_level: Mapped[str | None] = mapped_column(String(32))
    tags: Mapped[str | None] = mapped_column(Text)
    galaxies: Mapped[str | None] = mapped_column(Text)
    raw_json: Mapped[str | None] = mapped_column(Text)

    source: Mapped["SourceConfig"] = relationship(back_populates="events")
    iocs: Mapped[list["GenericIOC"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )


class GenericIOC(Base):
    __tablename__ = "generic_iocs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("intel_events.id"), index=True, nullable=True
    )
    source_id: Mapped[int] = mapped_column(ForeignKey("source_configs.id"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    threat_type: Mapped[str | None] = mapped_column(String(128))
    malware: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime)
    raw_json: Mapped[str | None] = mapped_column(Text)

    event: Mapped["IntelEvent"] = relationship(back_populates="iocs")
    source: Mapped["SourceConfig"] = relationship(back_populates="iocs")

    __table_args__ = (
        UniqueConstraint("source_id", "ioc_type", "value", name="uq_ioc_per_source"),
    )
    
class SearchQuery(Base):
    __tablename__ = "search_queries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    term: Mapped[str] = mapped_column(String(512), index=True)
    term_type: Mapped[str | None] = mapped_column(String(32)) # ip, domain, hash, email
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    results: Mapped[list["SearchResult"]] = relationship(back_populates="query", cascade="all, delete-orphan")


class SearchResult(Base):
    __tablename__ = "search_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    query_id: Mapped[int] = mapped_column(ForeignKey("search_queries.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32)) # abuseipdb, virustotal, intelx, pulsedive
    status: Mapped[str] = mapped_column(String(16)) # ok, error
    raw_json: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text) # Brief human-readable summary
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    query: Mapped["SearchQuery"] = relationship(back_populates="results")