"""
SQLAlchemy ORM models for scans and findings.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .dependencies import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    target = Column(String(1024), nullable=False)
    profile = Column(String(64), default="default")
    status = Column(String(32), default="PENDING")  # PENDING, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED
    start_time = Column(DateTime(timezone=True), server_default=func.now())
    end_time = Column(DateTime(timezone=True), nullable=True)
    summary_stats = Column(JSON, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.scan_id} {self.target} {self.status}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id"), nullable=False, index=True)
    severity = Column(String(16), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    type = Column(String(128), nullable=False)  # e.g., XSS, SQLi, IDOR, etc.
    endpoint = Column(String(1024), nullable=False)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding {self.id} {self.severity} {self.type}>"
