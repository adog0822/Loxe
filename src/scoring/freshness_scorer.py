from datetime import datetime, timezone


class FreshnessScorer:
    """Calculate freshness and gap detection scores"""

    def calculate_scores(self, evidence):
        """Calculate scores based on collected evidence"""

        scores = {
            'freshness': {
                'score': 0,
                'factors': []
            },
            'gap_detection': {
                'score': 0,
                'missing_controls': []
            }
        }

        # Calculate freshness based on evidence timestamps
        if 'timestamp' in evidence:
            evidence_time = datetime.fromisoformat(evidence['timestamp'].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            age_hours = (now - evidence_time).total_seconds() / 3600

            # Convert age to score (0-100, where 0-1 hour = 100, >24 hours = 0)
            if age_hours <= 1:
                freshness_score = 100
            elif age_hours >= 24:
                freshness_score = 0
            else:
                freshness_score = max(0, 100 - (age_hours * 4.1667))  # Linear decay over 24 hours

            scores['freshness']['score'] = round(freshness_score)
            scores['freshness']['factors'].append({
                'factor': 'Evidence Age',
                'value': f"{age_hours:.1f} hours",
                'impact': 'high' if age_hours > 12 else 'medium' if age_hours > 4 else 'low'
            })

        # Gap detection based on control coverage
        total_controls = 8
        covered_controls = len(set(evidence.get('control_mappings', [])))
        gap_score = (covered_controls / total_controls) * 100

        scores['gap_detection']['score'] = round(gap_score)

        # Identify missing controls (simplified for MVP)
        all_controls = ['CC6.1', 'CC6.3', 'CC6.7', 'CC7.1', 'CC7.2', 'CC7.4', 'CC8.1', 'CC8.2']
        evidence_controls = set(evidence.get('control_mappings', []))
        missing = [c for c in all_controls if c not in evidence_controls]

        scores['gap_detection']['missing_controls'] = missing

        return scores
