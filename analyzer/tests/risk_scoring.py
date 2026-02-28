import pytest
from decimal import Decimal
from analyzer.risk_scoring import RiskScoringEngine, get_risk_color, get_security_score_color

class TestRiskScoringEngine:
    
    def setup_method(self):
        self.engine = RiskScoringEngine()
    
    def test_calculate_anomaly_risk_score_basic(self):
        score = self.engine.calculate_anomaly_risk_score('shadowing', 'critical')
        assert score > Decimal('0')
        assert score <= Decimal('10.0')
    
    def test_calculate_anomaly_risk_score_with_context(self):
        context = {'affects_critical_services': True, 'zone': 'dmz'}
        score = self.engine.calculate_anomaly_risk_score('overly_permissive', 'warning', context)
        assert score > Decimal('5.0')  # Should be higher due to context
    
    def test_calculate_security_score_no_anomalies(self):
        result = self.engine.calculate_security_score([])
        assert result['security_score'] == Decimal('100.0')
        assert result['risk_level'] == 'excellent'
    
    def test_calculate_security_score_with_anomalies(self):
        anomalies = [
            {'type': 'shadowing', 'level': 'critical', 'risk_score': Decimal('8.5')},
            {'type': 'redundancy', 'level': 'info', 'risk_score': Decimal('2.0')}
        ]
        result = self.engine.calculate_security_score(anomalies)
        assert result['security_score'] < Decimal('100.0')
        assert result['total_risks'] == 2
        assert result['critical_risks'] == 1
    
    def test_enhance_anomalies_with_risk_scores(self):
        anomalies = [
            {'type': 'shadowing', 'level': 'critical', 'description': 'Test'},
            {'type': 'redundancy', 'level': 'info', 'description': 'Test2'}
        ]
        enhanced = self.engine.enhance_anomalies_with_risk_scores(anomalies)
        
        assert len(enhanced) == 2
        assert 'risk_score' in enhanced[0]
        assert enhanced[0]['risk_score'] > enhanced[1]['risk_score']  # Should be sorted
    
    def test_custom_weights(self):
        custom_weights = {'shadowing': 10.0, 'redundancy': 1.0}
        custom_engine = RiskScoringEngine(custom_weights)
        score = custom_engine.calculate_anomaly_risk_score('shadowing', 'critical')
        assert score > Decimal('8.0')

class TestUtilityFunctions:
    
    def test_get_risk_color(self):
        assert get_risk_color(Decimal('9.0')) == 'danger'
        assert get_risk_color(Decimal('6.0')) == 'warning'
        assert get_risk_color(Decimal('4.0')) == 'info'
        assert get_risk_color(Decimal('1.0')) == 'secondary'
    
    def test_get_security_score_color(self):
        assert get_security_score_color(Decimal('95.0')) == 'success'
        assert get_security_score_color(Decimal('80.0')) == 'info'
        assert get_security_score_color(Decimal('70.0')) == 'warning'
        assert get_security_score_color(Decimal('30.0')) == 'danger'