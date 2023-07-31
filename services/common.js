const passport = require("passport");
exports.isAuth = (req, res, done) => {
  return passport.authenticate("jwt");
};
exports.sanitizeUser = (user) => {
  return { id: user.id, role: user.role };
};

exports.cookieExtractor = function (req) {
  var token = null;
  if (req && req.cookies) {
    token = req.cookies["jwt"];
  }
  // token =
  // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0YzBiY2E1MzI4MDhmNjJiMmVlODQ4MCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY5MDY5MjA5MH0.k8ngdRKEv4p4lQEAw0Awy28PzVZiD4GB4iSY-eWun_M";
  return token;
};
