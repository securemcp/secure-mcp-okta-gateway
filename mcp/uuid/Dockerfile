# ビルドステージ
FROM node:22-alpine AS builder

WORKDIR /app

# 依存関係のインストール
COPY package.json package-lock.json* ./
RUN npm ci

# ソースコードのコピーとビルド
COPY . .
RUN npm run build

# 実行ステージ
FROM node:22-alpine AS runner

WORKDIR /app

# 必要な依存関係のみをインストール
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# ビルド成果物のコピー
COPY --from=builder /app/dist ./dist

# 非rootユーザーで実行
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 mcpuser && \
    chown -R mcpuser:nodejs /app
USER mcpuser

# ヘルスチェック
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:3000/mcp || exit 1

# 環境変数の設定
ENV NODE_ENV=production
ENV PORT=4000

# ポートの公開
EXPOSE 3000

# アプリケーションの起動
CMD ["node", "dist/index.js"]
