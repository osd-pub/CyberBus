#!/usr/bin/env python3
"""Opt-in G4/G5 runner. Each level launches actual SDK processes, never fixtures."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--suite',choices=['scale','stability'],default='scale')
    p.add_argument('--levels',default='2,16,64,128,256')
    p.add_argument('--output',type=Path,default=ROOT/'target'/('multiclient-slow-'+time.strftime('%Y%m%d-%H%M%S')))
    p.add_argument('--continue-after-failure',action='store_true')
    args,extra=p.parse_known_args()
    args.output.mkdir(parents=True,exist_ok=True)
    levels=[int(n) for n in args.levels.split(',')]
    if any(n<2 for n in levels):
        p.error('every scale level must contain at least two real clients')
    results=[]
    for n in levels:
        report=args.output/f'{args.suite}-n{n}.json'
        cmd=[sys.executable,str(ROOT/'tests/multiclient/runner.py'),'--suite',args.suite,
             '--n',str(n),'--local-relay','--report',str(report),*extra]
        status=subprocess.call(cmd)
        results.append(dict(n=n,exitCode=status,report=str(report)))
        if status and not args.continue_after_failure:
            break
    summary=dict(format='cyberbus-multiclient-slow/1',suite=args.suite,requestedLevels=levels,
                 runs=results,notRun=levels[len(results):])
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    return int(any(r['exitCode'] for r in results))


if __name__=='__main__':
    raise SystemExit(main())
