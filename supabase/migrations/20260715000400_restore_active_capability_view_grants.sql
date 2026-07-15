-- Historical migration content may already be recorded remotely, so restore
-- the exposed capability-view privileges in a new, independently tracked step.
grant select on public.active_service_capabilities
  to anon, authenticated, service_role;

grant select on public.active_resource_capabilities
  to anon, authenticated, service_role;
