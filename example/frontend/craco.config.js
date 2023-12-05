module.exports = {
	webpack: {
		configure: {
			module: {
				rules: [
					{
						test: /\.m?js$/,
						resolve: {
							fullySpecified: false,
						},
					},
				],
			},
		},
	},
	devServer: {
		port: 33435
	}
};
