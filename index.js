const express = require('express');
const app = express();

// Import login method routes
const loginMethod = require('./loginmethod/server');
app.use('/login', loginMethod);

// Import inventario routes
const inventario = require('./inventario/server');
app.use('/inventario', inventario);

// Import ponerorden routes
const ponerorden = require('./ponerorden/server');
app.use('/ponerorden', ponerorden);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`API Gateway running on port ${PORT}`);
});