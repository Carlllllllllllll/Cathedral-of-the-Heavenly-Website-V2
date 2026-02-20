
const PAGE_ACCESS = {

    '/user-management': ['leadadmin', 'admin'],
    '/user-approvals': ['leadadmin', 'admin'],
    '/gift-shop-approvals': ['leadadmin', 'admin'],
    '/gift-shop-add': ['leadadmin', 'admin'],


    '/admin/form-panel': ['leadadmin', 'admin', 'teacher'],


    '/grade/sec1': ['student:sec1', 'teacher', 'admin', 'leadadmin'],
    '/grade/sec2': ['student:sec2', 'teacher', 'admin', 'leadadmin'],
    '/grade/sec3': ['student:sec3', 'teacher', 'admin', 'leadadmin'],
    '/grade/prep1': ['student:prep1', 'teacher', 'admin', 'leadadmin'],
    '/grade/prep2': ['student:prep2', 'teacher', 'admin', 'leadadmin'],
    '/grade/prep3': ['student:prep3', 'teacher', 'admin', 'leadadmin'],


    '/gift-shop': ['student', 'teacher', 'admin', 'leadadmin'],


    '/leaderboard': ['student', 'teacher', 'admin', 'leadadmin'],
};

const API_ACCESS = {

    '/api/admin/users': ['leadadmin', 'admin'],
    '/api/admin/users/:id': ['leadadmin', 'admin'],
    '/api/banned-users': ['leadadmin', 'admin'],
    '/api/points/give': ['leadadmin', 'admin', 'teacher'],
    '/api/points/take': ['leadadmin', 'admin', 'teacher'],


    '/api/forms': ['leadadmin', 'admin', 'teacher'],


    '/api/gift-shop/approvals': ['leadadmin', 'admin'],
    '/api/gift-shop/items': ['leadadmin', 'admin'],


    '/api/user-info': ['student', 'teacher', 'admin', 'leadadmin'],
    '/api/gift-shop/purchase': ['student', 'teacher', 'admin', 'leadadmin'],
};

function hasRequiredRole(user, allowedRoles) {
    if (!user || !user.role) return false;

    const userRole = user.role;
    const userGrade = user.grade;


    if (allowedRoles.includes(userRole)) return true;


    if (userGrade && allowedRoles.includes(`${userRole}:${userGrade}`)) return true;

    return false;
}

function requireRole(allowedRoles) {
    return (req, res, next) => {

        let user = req.session.user;

        if (!user && req.session && req.session.username) {
            user = {
                username: req.session.username,
                role: req.session.role,
                grade: req.session.grade,
            };
        }

        if (!req.session || !user) {
            console.warn(`[RBAC] Unauthenticated access attempt to protected resource: ${req.path}`);
            return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
        }


        if (!hasRequiredRole(user, allowedRoles)) {
            console.warn(`[RBAC] Unauthorized access attempt by ${user.username} (${user.role}) to: ${req.path}`);
            return res.status(403).render('unauthorized', {
                user: user,
                requiredRoles: allowedRoles.join(', '),
                attemptedPath: req.path
            });
        }


        next();
    };
}

function requireAPIRole(allowedRoles) {
    return (req, res, next) => {

        let user = req.session.user;

        if (!user && req.session && req.session.username) {
            user = {
                username: req.session.username,
                role: req.session.role,
                grade: req.session.grade,
            };
        }

        if (!req.session || !user) {
            console.warn(`[RBAC API] Unauthenticated API access attempt: ${req.path}`);
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Authentication required'
            });
        }


        if (!hasRequiredRole(user, allowedRoles)) {
            console.warn(`[RBAC API] Unauthorized API access by ${user.username} (${user.role}) to: ${req.path}`);
            return res.status(403).json({
                error: 'Forbidden',
                message: 'You do not have permission to access this resource'
            });
        }


        next();
    };
}


function applyRBACToRoutes(app) {

    Object.keys(PAGE_ACCESS).forEach(path => {
        const allowedRoles = PAGE_ACCESS[path];
        console.log(`[RBAC] Protecting page: ${path} - Allowed: ${allowedRoles.join(', ')}`);
        app.use(path, requireRole(allowedRoles));
    });


    Object.keys(API_ACCESS).forEach(path => {
        const allowedRoles = API_ACCESS[path];
        console.log(`[RBAC] Protecting API: ${path} - Allowed: ${allowedRoles.join(', ')}`);
        app.use(path, requireAPIRole(allowedRoles));
    });
}

module.exports = {
    requireRole,
    requireAPIRole,
    hasRequiredRole,
    applyRBACToRoutes,
    PAGE_ACCESS,
    API_ACCESS,
};
