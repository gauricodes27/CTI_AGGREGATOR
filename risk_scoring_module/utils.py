from datetime import datetime, timezone

def calculate_recency_score(created_date):
    if not created_date:
        return 0

    if isinstance(created_date, str):
        try:
            created_date = datetime.fromisoformat(created_date)
        except ValueError:
            return 5

    if created_date.tzinfo is None:
        created_date = created_date.replace(tzinfo=timezone.utc)

    days_old = (datetime.now(timezone.utc) - created_date).days

    if days_old <= 1:
        return 15
    elif days_old <= 7:
        return 10
    elif days_old <= 30:
        return 5
    return 0
