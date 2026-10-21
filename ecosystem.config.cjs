module.exports = {
  apps: [{
    name: 'marketplace-helper-app',
    cwd: __dirname,
    script: 'src/server.js',
    exec_mode: 'fork',
    instances: 1,
    autorestart: true,
    watch: false,
    env: {
      NODE_ENV: 'production',
    },
  }],
};
