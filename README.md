# 畅聊ChatRoom 后端 (Render 部署版)

- 端口读取环境变量 PORT
- QQ 邮箱 SMTP 真实发送验证码（内置凭据）
- SQLite 数据库（默认同目录 chatroom.db，可用 DB_PATH 覆盖）

## 启动命令

gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 8
