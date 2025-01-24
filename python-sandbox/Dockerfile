# 使用轻量级 Python 基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /sandbox

# 运行代码的用户权限
RUN useradd -ms /bin/bash sandbox_user
USER sandbox_user

# 安装必要的 Python 包
RUN pip install --no-cache-dir --upgrade pip