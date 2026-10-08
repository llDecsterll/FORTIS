from fastapi import APIRouter

from . import account_cards, agent, approvals, auth, dashboard, devices, events, networks, requests, settings, sites, users

api = APIRouter()
api.include_router(account_cards.router)
api.include_router(approvals.router)
api.include_router(auth.router)
api.include_router(dashboard.router)
api.include_router(users.router)
api.include_router(devices.router)
api.include_router(sites.router)
api.include_router(requests.router)
api.include_router(networks.router)
api.include_router(events.router)
api.include_router(agent.router)
api.include_router(settings.router)
