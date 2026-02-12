def scope_query(query, tenant_id):
    return query.filter_by(tenant_id=tenant_id)
