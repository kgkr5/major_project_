import asyncio
from sqlalchemy import select, func
from backend.database.database import AsyncSessionLocal
from backend.database.models import (
    SecurityEvent,
    AgentInvestigation,
    AttackPath,
    DefenceRecommendation,
)

async def main():
    async with AsyncSessionLocal() as session:
        models = [
            ("Security Events", SecurityEvent),
            ("Investigations", AgentInvestigation),
            ("Attack Paths", AttackPath),
            ("Defence Recommendations", DefenceRecommendation),
        ]

        print("\n===== AGENTSHIELD DATABASE REPORT =====")

        for name, model in models:
            result = await session.execute(
                select(func.count()).select_from(model)
            )
            print(f"{name}: {result.scalar_one()}")

        print("========================================")

asyncio.run(main())