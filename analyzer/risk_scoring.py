"""
Module for calculating risk scores and security metrics for firewall configuration analysis.
"""

from decimal import Decimal
from typing import List, Dict, Any
from django.conf import settings

DEFAULT_RISK_WEIGHTS = {
    'shadowing': 8.0,
    'redundancy': 3.0,
    'overly_permissive': 9.5,
    'missing_description': 1.0,
    'nat_misconfiguration': 7.0,
    'security_misconfiguration': 6.5,
    'service_exposure': 8.0,
    'unknown_service': 4.0,
    'duplicate_object': 2.5,
    'unrestricted_management': 9.0,
    'weak_encryption': 7.5,
    'logging_disabled': 5.0,
    'default_credentials': 10.0,
    'unused_rule': 2.0,
    'protocol_violation': 8.5
}

SEVERITY_MULTIPLIERS = {
    'critical': 1.5,
    'warning': 1.0,
    'info': 0.3
}

class RiskScoringEngine:
    """
    Engine for calculating risk scores and security metrics
    """
    
    def __init__(self, custom_weights: Dict[str, float] = None):
        self.weights = custom_weights or getattr(settings, 'RISK_WEIGHTS', DEFAULT_RISK_WEIGHTS)

    def _normalize_type_key(self, anomaly_type: str) -> str:
        """Normalize anomaly type to match weight keys (e.g. 'Overly Permissive' -> 'overly_permissive')."""
        if not anomaly_type:
            return "unknown"
        return anomaly_type.strip().lower().replace("-", "_").replace(" ", "_")
    
    def calculate_anomaly_risk_score(self, anomaly_type: str, severity: str, 
                                   context: Dict[str, Any] = None) -> Decimal:
        """
        Calculate individual anomaly risk score
        """
        type_key = self._normalize_type_key(anomaly_type)
        base_weight = self.weights.get(type_key, 5.0)  # Default medium risk
        severity_multiplier = SEVERITY_MULTIPLIERS.get(severity, 1.0)
        
        risk_score = Decimal(base_weight * severity_multiplier)
        risk_score = self._apply_context_adjustments(risk_score, context)
        
        return min(risk_score, Decimal('10.0'))
    
    def _apply_context_adjustments(self, risk_score: Decimal, context: Dict[str, Any] = None) -> Decimal:
        if not context:
            return risk_score
        
        if context.get('affects_critical_services'):
            risk_score *= Decimal('1.2')
        
        if context.get('is_externally_accessible'):
            risk_score *= Decimal('1.1')
        
        if context.get('user_count', 0) > 1000:
            risk_score *= Decimal('1.15')
        
        return risk_score
    
    def enhance_anomalies_with_risk_scores(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enhanced_anomalies = []
        
        for anomaly in anomalies:
            risk_score = self.calculate_anomaly_risk_score(
                anomaly_type=anomaly.get('type', 'unknown'),
                severity=anomaly.get('level', 'info'),
                context=anomaly.get('context', {})
            )
            
            enhanced_anomaly = anomaly.copy()
            enhanced_anomaly['risk_score'] = risk_score.quantize(Decimal('0.01'))
            enhanced_anomalies.append(enhanced_anomaly)
        
        enhanced_anomalies.sort(key=lambda x: x['risk_score'], reverse=True)
        return enhanced_anomalies
    
    def calculate_security_score(self, anomalies: List[Dict[str, Any]], total_rules: int = 100) -> Dict[str, Any]:
        total_anomalies = len(anomalies)
        critical_anomalies = len([a for a in anomalies if a.get('level') == 'critical'])
        
        if total_anomalies == 0:
            security_score = Decimal('100.0')
        else:
            total_risk = sum([a.get('risk_score', Decimal('0')) for a in anomalies])
            max_possible_risk = Decimal(total_rules * 10)
            
            risk_percentage = (total_risk / max_possible_risk) * 100 if max_possible_risk > 0 else 0
            security_score = max(Decimal('0'), Decimal('100') - risk_percentage)
        
        if security_score >= 80:
            risk_level = 'low'
        elif security_score >= 60:
            risk_level = 'medium'
        elif security_score >= 40:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        return {
            'security_score': security_score.quantize(Decimal('0.01')),
            'risk_level': risk_level,
            'total_anomalies': total_anomalies,
            'critical_anomalies': critical_anomalies,
            'total_rules': total_rules
        }
