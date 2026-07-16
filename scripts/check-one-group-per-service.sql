-- Diagnostic: find users with multiple active groups in the same service.
-- Run BEFORE the usage-policy migration. If this returns any rows, resolve
-- each conflict in Console before applying the migration.

select upg.user_id, pg.service_key, array_agg(pg.key order by pg.key) as active_groups
from public.user_permission_groups upg
join public.permission_groups pg on pg.id = upg.group_id
where upg.status = 'active'
  and (upg.expires_at is null or upg.expires_at > now())
group by upg.user_id, pg.service_key
having count(*) > 1;
