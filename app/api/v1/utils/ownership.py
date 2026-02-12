def owned_query(model, user):
    return model.query.filter_by(tenant_id=user.tenant_id)
