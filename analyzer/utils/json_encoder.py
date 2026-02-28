# analyzer/utils/json_encoder.py
import json
from decimal import Decimal
from datetime import datetime, date
from django.core.serializers.json import DjangoJSONEncoder

class DecimalJSONEncoder(DjangoJSONEncoder):
    """
    Custom JSON encoder that handles Decimal objects
    """
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)