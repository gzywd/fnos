"""飞牛 fnOS 集成配置流程。"""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .api import (
    ERR_BAD_ACCESS_CODE,
    ERR_BAD_CREDENTIAL,
    ERR_NEED_2FA,
    FnOsApiError,
    FnOsClient,
    gen_did,
)
from .const import (
    CONF_2FA_CODE,
    CONF_ACCESS_CODE,
    CONF_DID,
    CONF_DISK_INFO,
    CONF_MEDIA_INFO,
    CONF_UPDATE_INTERVAL,
    CONF_WEB_BASE_URL,
    CONF_SSL,
    DEFAULT_PORT,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    MAX_UPDATE_INTERVAL,
    MIN_UPDATE_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_SSL, default=False): bool,
        vol.Required(CONF_USERNAME, default="admin"): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_ACCESS_CODE, default=""): str,
    }
)

STEP_2FA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_2FA_CODE): str,
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_UPDATE_INTERVAL, default=DEFAULT_UPDATE_INTERVAL):
            vol.All(vol.Coerce(int), vol.Range(min=MIN_UPDATE_INTERVAL,
                                               max=MAX_UPDATE_INTERVAL)),
        vol.Optional(CONF_WEB_BASE_URL, default=""): str,
    }
)


def _validate(hass, data):
    """登录 + 拉一轮快照验证配置（executor 里跑同步客户端）。"""

    def _try():
        client = FnOsClient(
            host=data[CONF_HOST], port=data[CONF_PORT],
            username=data[CONF_USERNAME], password=data[CONF_PASSWORD],
            ssl=data.get(CONF_SSL, False),
            access_code=data.get(CONF_ACCESS_CODE),
            twofa_code=data.get(CONF_2FA_CODE),
            did=data.get(CONF_DID),
        )
        try:
            client.must("appcgi.sysinfo.getHostName")
            return True
        finally:
            client.close()

    return hass.async_add_executor_job(_try)


class FnOsConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """处理配置流程。"""

    VERSION = 1

    def __init__(self):
        self._pending: dict = {}

    async def _validate_and_make(self, data, errors):
        """校验并建条目；需要两步验证时跳到 twofa 步骤。返回 flow result 或 None。"""
        try:
            await _validate(self.hass, data)
        except FnOsApiError as err:
            if err.errno == ERR_BAD_CREDENTIAL:
                errors["base"] = "invalid_auth"
            elif err.errno == ERR_BAD_ACCESS_CODE:
                errors["base"] = "invalid_access_code"
            elif err.errno == ERR_NEED_2FA:
                self._pending = data
                return await self.async_step_twofa()
            else:
                errors["base"] = "cannot_connect"
            return None
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("fnOS 连接校验失败")
            errors["base"] = "cannot_connect"
            return None
        entry_data = {k: v for k, v in data.items() if k != CONF_2FA_CODE}
        return self.async_create_entry(
            title=f"飞牛 fnOS · {data[CONF_HOST]}", data=entry_data
        )

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            # 设备身份只生成一次并随条目保存：服务端靠它记住「受信设备」，
            # 换了 did 就等于换了新设备，开了 2FA 会反复要动态码
            user_input.setdefault(CONF_DID, gen_did())
            await self.async_set_unique_id(
                f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}")
            self._abort_if_unique_id_configured()
            result = await self._validate_and_make(user_input, errors)
            if result is not None:
                return result
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    async def async_step_twofa(self, user_input=None):
        """账号开启了两步验证：再要一次 6 位动态码（只会走一次，成功后设备受信）。"""
        errors = {}
        if user_input is not None:
            data = dict(self._pending)
            data[CONF_2FA_CODE] = user_input.get(CONF_2FA_CODE, "")
            if len(str(data[CONF_2FA_CODE]).strip()) != 6:
                errors["base"] = "invalid_2fa"
            else:
                result = await self._validate_and_make(data, errors)
                if result is not None:
                    return result
        return self.async_show_form(
            step_id="twofa", data_schema=STEP_2FA_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return FnOsOptionsFlow(config_entry)


class FnOsOptionsFlow(config_entries.OptionsFlow):
    """选项：数据刷新间隔 / 访问基地址 / 是否读硬盘信息。"""

    def __init__(self) -> None:
        """HA 自己注入 config_entry，这里不能再接收参数。"""

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_UPDATE_INTERVAL,
                    default=self.config_entry.options.get(
                        CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL),
                ): vol.All(vol.Coerce(int),
                           vol.Range(min=MIN_UPDATE_INTERVAL,
                                     max=MAX_UPDATE_INTERVAL)),
                vol.Optional(
                    CONF_WEB_BASE_URL,
                    default=self.config_entry.options.get(
                        CONF_WEB_BASE_URL, ""),
                ): str,
                vol.Optional(
                    CONF_DISK_INFO,
                    default=self.config_entry.options.get(
                        CONF_DISK_INFO, False),
                ): bool,
                vol.Optional(
                    CONF_MEDIA_INFO,
                    default=self.config_entry.options.get(
                        CONF_MEDIA_INFO, False),
                ): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
