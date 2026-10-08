from .models import User


def approval_author(db, row):
    """Only a successful approval has an approver; never substitute its creator."""
    if not row or getattr(row.status, 'value', row.status) not in ('ISSUED', 'APPROVED_SB'):
        return {"reviewedByName": "", "reviewedBy": ""}
    login = row.reviewed_by or ''
    reviewer = db.query(User).filter(User.email == login).one_or_none() if login else None
    return {"reviewedByName": reviewer.full_name if reviewer else '', "reviewedBy": login}
