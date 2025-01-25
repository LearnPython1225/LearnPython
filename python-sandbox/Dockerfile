# 使用轻量级 Python 基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /sandbox

# 创建一个用户以增强安全性
RUN useradd -ms /bin/bash sandbox_user
USER sandbox_user

# 复制代码文件到容器
COPY . .

# 安装必要的 Python 包
RUN pip install --no-cache-dir --upgrade pip
RUN pip install -r requirements.txt

# 合并 CMD 指令
CMD sh -c "python app.py && docker run sandbox-image"