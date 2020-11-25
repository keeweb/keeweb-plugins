(async function () {
    await require('./sign')(Buffer.from('test'));
    await require('./download-translations')();
    require('./update-plugins');
})().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Error', err);
});
