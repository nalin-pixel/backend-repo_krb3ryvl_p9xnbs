"""
Database Schemas for Privacy-Preserving Voting DApp

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).

Collections:
- Voter: Off-chain voter registry (no biometrics). Stores public key and iris commitment.
- Election: Election metadata and candidate list.
- VoteRecord: Off-chain mirror of on-chain vote metadata for audit/explorer.
- AuthSession: Ephemeral challenge nonces for simulated ZKP handshake.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime


class Voter(BaseModel):
    voter_id: str = Field(..., description="Government/Institution issued ID")
    name: str = Field(..., description="Full name")
    email: Optional[str] = Field(None, description="Contact email")
    demographics: Optional[dict] = Field(default_factory=dict)
    public_key: str = Field(..., description="Voter ECC public key (hex)")
    public_key_hash: str = Field(..., description="Hash of public key for anonymity")
    iris_commitment: str = Field(..., description="Client-side commitment (e.g., SHA-256 of iris template + client salt)")
    registered_at: Optional[datetime] = None


class Candidate(BaseModel):
    id: str = Field(..., description="Candidate id")
    name: str = Field(..., description="Candidate name")
    party: Optional[str] = None


class Election(BaseModel):
    title: str = Field(...)
    description: Optional[str] = None
    status: Literal['draft', 'active', 'closed'] = Field('draft')
    candidates: List[Candidate] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class VoteRecord(BaseModel):
    election_id: str = Field(...)
    voter_public_key_hash: str = Field(..., description="Anonymous voter identifier")
    candidate_id: str = Field(...)
    zk_proof: Optional[dict] = Field(default_factory=dict)
    signed_payload: Optional[str] = None
    tx_hash: Optional[str] = None
    chain_id: Optional[int] = None
    contract_address: Optional[str] = None


class AuthSession(BaseModel):
    voter_id: str
    nonce: str
    created_at: Optional[datetime] = None
    verified: bool = False
