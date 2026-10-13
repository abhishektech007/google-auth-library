#!/usr/bin/env python3
"""Runner script delegating to main:app via uvicorn."""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    host = os.getenv("HOST", "0.0.0.0")
    env = os.getenv("ENVIRONMENT", "development")
    uvicorn.run("main:app", host=host, port=port, reload=(env == "development"))
