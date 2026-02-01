/** @type {import('next').NextConfig} */
const nextConfig = {
  outputFileTracingRoot: __dirname,
  serverExternalPackages: ['@prisma/client', 'bcryptjs']
}

module.exports = nextConfig