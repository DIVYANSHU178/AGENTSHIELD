import sys
from pathlib import Path

# Add apps/api to path
API_DIR = Path(__file__).resolve().parent.parent / "apps" / "api"
sys.path.insert(0, str(API_DIR))

import json
from app.main import app
from fastapi.routing import APIRoute

def get_all_routes():
    inventory = []
    def traverse(router, current_prefix=""):
        routes = []
        for r in router.routes:
            if isinstance(r, APIRoute):
                # Attach computed path
                full_path = current_prefix + r.path
                routes.append((full_path, r))
            elif hasattr(r, "original_router"):
                sub_prefix = current_prefix + (r.include_context.prefix if hasattr(r, "include_context") and r.include_context else "")
                routes.extend(traverse(r.original_router, sub_prefix))
            elif hasattr(r, "routes"):
                routes.extend(traverse(r, current_prefix))
        return routes

    all_api_routes = traverse(app)
    for full_path, r in all_api_routes:
        methods = sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")])
        if not methods:
            methods = sorted(list(r.methods))

        body_models = []
        for p in r.dependant.body_params:
            typ = getattr(p, "type_", getattr(p, "annotation", None))
            if typ is not None:
                body_models.append(typ.__name__ if hasattr(typ, "__name__") else str(typ))
            else:
                body_models.append(str(p))
        query_params = [p.name for p in r.dependant.query_params]
        path_params = [p.name for p in r.dependant.path_params]
        response_model = r.response_model.__name__ if hasattr(r.response_model, "__name__") else str(r.response_model)

        # Determine permission / auth
        dependencies = []
        auth_required = False
        permission_required = None
        for d in r.dependant.dependencies:
            dep_call = getattr(d, "call", None)
            dep_name = getattr(dep_call, "__name__", str(dep_call))
            dependencies.append(dep_name)
            if "get_current_user" in dep_name:
                auth_required = True
            if "_permission_guard" in dep_name:
                auth_required = True
                if hasattr(dep_call, "__closure__") and dep_call.__closure__:
                    for cell in dep_call.__closure__:
                        if hasattr(cell.cell_contents, "value"):
                            permission_required = cell.cell_contents.value

        rate_limit_class = "general"
        if "/auth/login" in full_path:
            rate_limit_class = "auth_login"
        elif "/identities" in full_path:
            rate_limit_class = "identity_management"
        elif "/dev/" in full_path:
            rate_limit_class = "dev_harness"

        cache_policy = "public" if full_path.startswith("/health") else "no-store"

        is_dev_only = "/dev/" in full_path

        for m in methods:
            inventory.append({
                "method": m,
                "path": full_path,
                "endpoint_name": r.name,
                "auth_required": auth_required,
                "permission_required": permission_required,
                "body_models": body_models,
                "query_params": query_params,
                "path_params": path_params,
                "response_model": response_model,
                "dependencies": dependencies,
                "rate_limit_class": rate_limit_class,
                "cache_policy": cache_policy,
                "dev_only": is_dev_only,
            })
    return inventory

if __name__ == "__main__":
    inv = get_all_routes()
    print(f"TOTAL REGISTERED APPLICATION ROUTES: {len(inv)}")
    out_file = Path(__file__).resolve().parent.parent / "endpoint_inventory.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=2)
    print(f"Inventory written to: {out_file}")
    for item in inv:
        perm = f" [Perm: {item['permission_required']}]" if item['permission_required'] else ""
        print(f"  {item['method']:<6} {item['path']:<45} -> {item['endpoint_name']}{perm}")
