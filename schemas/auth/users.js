const joi = require("joi");

module.exports = joi.object().keys({
  username: joi
    .string()
    .trim()
    .max(64)
    .required(),
  display_name: joi
    .string()
    .trim()
    .max(64)
    .required(),
  email: joi
    .string()
    .trim()
    .email()
    .max(64)
    .required(),
  password: joi
    .string()
    .trim()
    .max(64)
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
      "password"
    )
    .required(),
  enabled: joi.boolean().required(),
  roleId: joi
    .string()
    .trim()
    .token()
    .required()
});
