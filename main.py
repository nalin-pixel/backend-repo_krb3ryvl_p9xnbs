import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from database import db, create_document, get_documents
from schemas import Voter, Election, VoteRecord, AuthSession, Candidate
from datetime import datetime
import hashlib
import secrets

app = FastAPI(title="Privacy-Preserving Iris Voting API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "Voting API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Utility: deterministic hash helper

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# --------- Registration ---------

class RegisterRequest(BaseModel):
    voter_id: str
    name: str
    email: Optional[str] = None
    demographics: Optional[dict] = None
    public_key: str
    iris_commitment: str  # pre-hashed commitment computed locally


@app.post("/api/register")
def register_voter(payload: RegisterRequest):
    # prevent duplicates by voter_id or public_key hash
    pk_hash = sha256_hex(payload.public_key.lower())
    existing = db["voter"].find_one({"$or": [{"voter_id": payload.voter_id}, {"public_key_hash": pk_hash}]})
    if existing:
        raise HTTPException(status_code=400, detail="Voter already registered")

    voter = Voter(
        voter_id=payload.voter_id,
        name=payload.name,
        email=payload.email,
        demographics=payload.demographics or {},
        public_key=payload.public_key,
        public_key_hash=pk_hash,
        iris_commitment=payload.iris_commitment,
        registered_at=datetime.utcnow(),
    )
    voter_id = create_document("voter", voter)
    return {"ok": True, "id": voter_id, "public_key_hash": pk_hash}


# --------- Auth (Simulated ZKP handshake) ---------

class ChallengeResponse(BaseModel):
    voter_id: str


@app.post("/api/auth/challenge")
def auth_challenge(payload: ChallengeResponse):
    # create an ephemeral nonce for the voter id if exists
    exists = db["voter"].find_one({"voter_id": payload.voter_id})
    if not exists:
        raise HTTPException(status_code=404, detail="Voter not found")
    nonce = secrets.token_hex(16)
    session = AuthSession(voter_id=payload.voter_id, nonce=nonce, created_at=datetime.utcnow(), verified=False)
    create_document("authsession", session)
    return {"nonce": nonce}


class VerifyRequest(BaseModel):
    voter_id: str
    iris_commitment_proof: str  # client generates proof string from iris re-scan
    signed_nonce: str  # signature of nonce with voter's private key (client-side)


@app.post("/api/auth/verify")
def auth_verify(payload: VerifyRequest):
    # IMPORTANT: This is a placeholder verification simulating ZKP & signature check
    # In production, integrate a ZKP verifier and secp256k1/ed25519 signature verification
    voter = db["voter"].find_one({"voter_id": payload.voter_id})
    if not voter:
        raise HTTPException(status_code=404, detail="Voter not found")

    # Fetch latest session nonce
    session = db["authsession"].find_one({"voter_id": payload.voter_id}, sort=[("created_at", -1)])
    if not session:
        raise HTTPException(status_code=400, detail="No active session")

    # Simulated checks: proof must hash-prefix-match stored commitment, signed_nonce length check
    proof_ok = voter["iris_commitment"][:8] == payload.iris_commitment_proof[:8]
    sig_ok = len(payload.signed_nonce) >= 64
    if not (proof_ok and sig_ok):
        raise HTTPException(status_code=401, detail="Verification failed")

    db["authsession"].update_one({"_id": session["_id"]}, {"$set": {"verified": True}})
    return {"ok": True, "public_key_hash": voter["public_key_hash"]}


# --------- Elections ---------

class CreateElectionRequest(BaseModel):
    title: str
    description: Optional[str] = None
    candidates: List[Candidate]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@app.post("/api/elections")
def create_election(payload: CreateElectionRequest):
    election = Election(
        title=payload.title,
        description=payload.description,
        candidates=payload.candidates,
        status="active",
        start_time=payload.start_time or datetime.utcnow(),
        end_time=payload.end_time,
    )
    election_id = create_document("election", election)
    return {"ok": True, "id": election_id}


@app.get("/api/elections")
def list_elections():
    items = get_documents("election")
    for it in items:
        it["_id"] = str(it["_id"])  # make JSON serializable
    return {"items": items}


# --------- Voting ---------

class CastVoteRequest(BaseModel):
    election_id: str
    voter_public_key_hash: str
    candidate_id: str
    zk_proof: Optional[dict] = None
    signed_payload: Optional[str] = None


@app.post("/api/vote")
def cast_vote(payload: CastVoteRequest):
    # Prevent double voting per election/public_key_hash
    exists = db["voterecord"].find_one({
        "election_id": payload.election_id,
        "voter_public_key_hash": payload.voter_public_key_hash
    })
    if exists:
        raise HTTPException(status_code=400, detail="Voter already cast a vote for this election")

    # Store off-chain mirror (we will set tx_hash after blockchain write from frontend)
    rec = VoteRecord(
        election_id=payload.election_id,
        voter_public_key_hash=payload.voter_public_key_hash,
        candidate_id=payload.candidate_id,
        zk_proof=payload.zk_proof or {},
        signed_payload=payload.signed_payload,
    )
    rec_id = create_document("voterecord", rec)
    return {"ok": True, "id": rec_id}


class AttachTxRequest(BaseModel):
    vote_id: str
    tx_hash: str
    contract_address: Optional[str] = None
    chain_id: Optional[int] = None


@app.post("/api/vote/attach-tx")
def attach_tx(payload: AttachTxRequest):
    from bson import ObjectId
    try:
        oid = ObjectId(payload.vote_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid vote id")

    res = db["voterecord"].update_one({"_id": oid}, {"$set": {
        "tx_hash": payload.tx_hash,
        "contract_address": payload.contract_address,
        "chain_id": payload.chain_id,
    }})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vote not found")
    return {"ok": True}


@app.get("/api/votes")
def list_votes(election_id: Optional[str] = None):
    q = {"election_id": election_id} if election_id else {}
    items = list(db["voterecord"].find(q).sort("_id", -1))
    for it in items:
        it["_id"] = str(it["_id"])  # stringify
    return {"items": items}
