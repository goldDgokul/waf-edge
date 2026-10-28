// 0B.2 (ADR 0002): the fake API endpoints were location-level `return 200`
// directives. nginx executes `return` in the rewrite phase, BEFORE the access
// phase where the CRS engine's request rules run, so the whole endpoint class
// became uninspectable (measured: /?id=1 OR 1=1 blocked 403 while
// /api/search?id=1 OR 1=1 bypassed at 200).
//
// These handlers re-implement exactly the previous canned responses in the
// content phase, after limit_req and all ModSecurity phases have run.
function respond(r, body) {
    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, body);
}

function users(r) {
    respond(r, '{"users": ["alice", "bob", "charlie"]}');
}

function login(r) {
    respond(r, '{"status": "success", "token": "fake-jwt-token"}');
}

function search(r) {
    respond(r, '{"results": ["item1", "item2", "item3"]}');
}

function admin(r) {
    r.headersOut['Content-Type'] = 'text/html';
    r.return(200, '<!DOCTYPE html><html><body><h1>Admin Panel</h1><p>Node 1 Admin</p></body></html>');
}

function dashboard(r) {
    r.headersOut['Content-Type'] = 'text/html';
    r.return(200, '<!DOCTYPE html><html><body><h1>Dashboard</h1><p>Node 2 Dashboard</p></body></html>');
}

function dispatch(r) {
    const map = {'/api/users': users, '/api/login': login, '/api/search': search};
    const handler = map[r.uri];
    if (handler) {
        return handler(r);
    }
    r.return(404);
}

export default {dispatch, admin, dashboard};
