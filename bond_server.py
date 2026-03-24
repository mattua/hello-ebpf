#!/usr/bin/env python3
"""FastAPI bond price server — returns random lists of bond instruments at GET /prices."""
import random
import string
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

_CUSIP_CHARS = string.ascii_uppercase + string.digits


def _random_cusip() -> str:
    return "".join(random.choices(_CUSIP_CHARS, k=9))


def _random_isin(cusip: str) -> str:
    return f"US{cusip}"


def _random_price() -> float:
    return round(random.uniform(85.0, 115.0), 4)


def _random_yield() -> float:
    return round(random.uniform(1.5, 8.5), 4)


def _random_spread() -> float:
    return round(random.uniform(10.0, 350.0), 2)


class BondPrice(BaseModel):
    cusip: str
    datetime: str
    isin: str
    price: float
    yield_: float
    spread: float
    recordid: str
    transactionid: str

    model_config = {"populate_by_name": True}


@app.get("/prices")
def get_prices() -> list[dict]:
    count = random.randint(5, 15)
    now = datetime.now(timezone.utc).isoformat()
    results = []
    for _ in range(count):
        cusip = _random_cusip()
        results.append({
            "cusip": cusip,
            "datetime": now,
            "isin": _random_isin(cusip),
            "price": _random_price(),
            "yield": _random_yield(),
            "spread": _random_spread(),
            "recordid": str(uuid.uuid4()),
            "transactionid": str(uuid.uuid4()),
        })
    return results


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("bond_server:app", host="127.0.0.1", port=8080, reload=False)
