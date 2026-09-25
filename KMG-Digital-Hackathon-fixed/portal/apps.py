from django.apps import AppConfig
class PortalConfig(AppConfig):
    name = 'portal'
    def ready(self):
        from django.db.models.signals import post_save, post_delete, m2m_changed
        from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
        from . import audit
        post_save.connect(audit.mutation, dispatch_uid='portal_mutation')
        post_delete.connect(audit.deletion, dispatch_uid='portal_deletion')
        m2m_changed.connect(audit.relations, dispatch_uid='portal_relations')
        user_logged_in.connect(audit.signed_in)
        user_logged_out.connect(audit.signed_out)
        user_login_failed.connect(audit.login_failed)
        # ИБ-07: DBMS event journal — connections, schema changes (migrations)
        from django.db.backends.signals import connection_created
        from django.db.models.signals import post_migrate
        connection_created.connect(audit.db_connected, dispatch_uid='portal_db_connect')
        post_migrate.connect(audit.db_schema_changed, dispatch_uid='portal_db_schema')
