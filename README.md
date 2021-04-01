# 简单的oauth2 server
- **支持新老token共存，减少token即将到有效时间导致的token验证失败**
- 支持配置文件自定义token有效时间&间隙时间
- 支持配置热修改
- 暴露端口如下：
  - /oauth/token: 获取token
  - /oauth/check_token: token验证
  - /oauth/reload_config: （热）加载配置
- 仅支持client模式，适合内部服务间鉴权
- 可直接替换原pring security oauth2，业务代码无需修改