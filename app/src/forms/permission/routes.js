const routes = require('express').Router();

const jwtService = require('../../components/jwtService');
const currentUser = require('../auth/middleware/userAccess').currentUser;
const rateLimiter = require('../common/middleware').apiKeyRateLimiter;
const validateParameter = require('../common/middleware/validateParameter');
const controller = require('./controller');

routes.use(rateLimiter);
routes.use(jwtService.protect('admin'));
routes.use(currentUser);

routes.param('code', validateParameter.validatePermissionCode);

routes.get('/', async (req, res, next) => {
  await controller.list(req, res, next);
});

routes.post('/', async (req, res, next) => {
  await controller.create(req, res, next);
});

routes.get('/:code', async (req, res, next) => {
  await controller.read(req, res, next);
});

routes.put('/:code', async (req, res, next) => {
  await controller.update(req, res, next);
});

module.exports = routes;
