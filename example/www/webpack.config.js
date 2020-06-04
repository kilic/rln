const path = require('path');
module.exports = {
  entry: './index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.js',
  },
  // module: {
  //   rules: [{ test: /\.key$/, use: 'raw-loader' }],
  // },
  // module: {
  //   rules: [
  //     {
  //       test: /\.(key)$/i,
  //       use: [
  //         {
  //           loader: 'file-loader',
  //         },
  //       ],
  //     },
  //   ],
  // },

  mode: 'development',
};
