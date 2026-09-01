#!/usr/bin/env python3
"""Suresi dolan oturumlari dusuren zamanlanmis gorev."""
import sys
sys.path.insert(0, "/home/yasin/netgate")
from app import portal
dusen = portal.expire_sessions()
if dusen:
    print(f"{len(dusen)} oturum dusuruldu:")
    for d in dusen:
        print(" ", d)
