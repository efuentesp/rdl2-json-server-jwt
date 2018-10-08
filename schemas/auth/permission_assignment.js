const joi = require("joi");

module.exports = joi.object().keys({
  roleId: joi
    .string()
    .trim()
    .token()
    .required(),
  permissionId: joi
    .string()
    .trim()
    .token()
    .required()
});
