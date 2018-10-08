const joi = require("joi");

module.exports = joi.object().keys({
  name: joi
    .string()
    .trim()
    .max(64)
    .required(),
  description: joi
    .string()
    .trim()
    .max(64)
    .required(),
  enabled: joi.boolean().required()
});
