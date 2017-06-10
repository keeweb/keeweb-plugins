(async function() {
    await require('./download-translations')();
    require('./update-plugins');
})();
