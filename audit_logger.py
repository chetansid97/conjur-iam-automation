#!/usr/bin/env python3
"""
Conjur Audit Log Analyzer
Analyzes access logs from Conjur IAM automation for security monitoring and compliance
"""

import json
import argparse
from collections import Counter
from datetime import datetime, timedelta
import os
from typing import List, Dict, Any

class ConjurAuditAnalyzer:
    """Analyzes Conjur access logs for security insights"""
    
    def __init__(self, log_file: str = "conjur_audit.jsonl"):
        self.log_file = log_file
        self.logs = self._load_logs()
    
    def _load_logs(self) -> List[Dict[str, Any]]:
        """Load and parse audit log entries"""
        logs = []
        if not os.path.exists(self.log_file):
            print(f"⚠️ Log file {self.log_file} not found. No data to analyze.")
            return logs
            
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return logs
    
    def filter_by_time(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Filter logs to only include entries from last N hours"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            log for log in self.logs 
            if datetime.fromisoformat(log['timestamp']) > cutoff
        ]
    
    def generate_report(self, hours: int = 24):
        """Generate comprehensive audit report"""
        recent = self.filter_by_time(hours)
        
        if not recent:
            print(f"\nNo access logs found in the last {hours} hours.")
            return
        
        print("\n" + "="*60)
        print(f"🔐 CONJUR AUDIT REPORT (Last {hours} Hours)")
        print("="*60)
        
        # Summary stats
        print(f"\n📊 Summary:")
        print(f"  Total accesses: {len(recent)}")
        print(f"  Unique users: {len(set(log['username'] for log in recent))}")
        print(f"  Unique secrets: {len(set(log['variable_path'] for log in recent))}")
        
        # Access by user
        user_counts = Counter([log['username'] for log in recent])
        print(f"\n👤 Top Users:")
        for user, count in user_counts.most_common(5):
            print(f"  {user}: {count} accesses")
        
        # Most accessed secrets
        secret_counts = Counter([log['variable_path'] for log in recent])
        print(f"\n🔑 Most Accessed Secrets:")
        for secret, count in secret_counts.most_common(5):
            print(f"  {secret}: {count} times")
        
        # Failure analysis
        failures = [log for log in recent if log.get('status') == 'failure']
        if failures:
            print(f"\n⚠️ Failed Attempts: {len(failures)}")
            for fail in failures[:3]:  # Show first 3
                print(f"  {fail['timestamp']} - {fail['username']} - {fail['variable_path']}")
        
        # Time-based analysis
        hours_dist = Counter([datetime.fromisoformat(log['timestamp']).hour for log in recent])
        peak_hour = hours_dist.most_common(1)[0]
        print(f"\n⏰ Peak Access Hour: {peak_hour[0]}:00 UTC ({peak_hour[1]} accesses)")
        
        print("\n" + "="*60)
    
    def export_report(self, output_file: str = "audit_report.json"):
        """Export analysis results to JSON"""
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_logs": len(self.logs),
            "analysis": {
                "unique_users": len(set(log['username'] for log in self.logs)),
                "unique_secrets": len(set(log['variable_path'] for log in self.logs)),
                "total_failures": len([l for l in self.logs if l.get('status') == 'failure']),
                "first_access": min((l['timestamp'] for l in self.logs), default=None),
                "last_access": max((l['timestamp'] for l in self.logs), default=None),
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📁 Report exported to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Conjur Audit Log Analyzer")
    parser.add_argument("--hours", type=int, default=24, help="Analysis window in hours")
    parser.add_argument("--logfile", default="conjur_audit.jsonl", help="Audit log file path")
    parser.add_argument("--export", action="store_true", help="Export report to JSON")
    
    args = parser.parse_args()
    
    analyzer = ConjurAuditAnalyzer(log_file=args.logfile)
    analyzer.generate_report(hours=args.hours)
    
    if args.export:
        analyzer.export_report()

if __name__ == "__main__":
    main()
