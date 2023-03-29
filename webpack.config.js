const path = require('path');

module.exports = {
    entry: './index.ts',
    devtool: 'inline-source-map',
    mode: 'production',
    target: "node",
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
    },
    output: {
        filename: 'index.js',
        path: path.resolve(__dirname, 'builded'),
        library: 'ZtMiddleware',
        libraryTarget: 'umd',
        umdNamedDefine: true,
    },
};
