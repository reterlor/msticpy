#  -------------------------------------------------------------------------
#  Copyright (c) Anton Kutepov. All rights reserved.
#  Licensed under the MIT License.
#  --------------------------------------------------------------------------

"""MPSIEM Driver class."""
import calendar
import datetime
import logging
import sys
from typing import Any, Dict, Iterable, Optional, Tuple, Union

import pandas as pd
import urllib3
from pandas import json_normalize

from ...common.exceptions import (
    MsticpyConnectionError,
    MsticpyImportExtraError,
    MsticpyNotConnectedError,
    MsticpyUserConfigError,
)
from ...common.provider_settings import ProviderSettings, get_provider_settings
from ...common.utility import check_kwargs, export
from .driver_base import DriverBase, DriverProps, QuerySource

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from mpsiemlib.common import AuthType, Creds, MPSIEMAuth, Settings
    from mpsiemlib.modules import EventsAPI
except ImportError as imp_err:
    raise MsticpyImportExtraError(
        "Cannot use this feature without mpsiemlib installed",
        title="Error importing mpsiemlib",
        extra="mpsiem",
    ) from imp_err

__version__ = "0.0.1"
__author__ = "Anton Kutepov"  # inspired by Ashwin Patil Splunk Driver


MPSIEM_CONNECT_ARGS = {
    "host": "(string) The host name of MP SIEM Core.",
    "username": "(string) The MaxPatrol SIEM account username",
    "password": "(string) The password for the MaxPatrol SIEM account.",
}

FORMATTER = logging.Formatter(
    "%(asctime)s - %(process)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def get_console_handler() -> logging.StreamHandler:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


class LoggerHandler:
    """Класс, создающий logger объект при наследовании"""

    logger = logging.getLogger(__name__)
    logger.setLevel("INFO")
    logger.addHandler(get_console_handler())
    logger.propagate = False


@export
class MPSIEMDriver(DriverBase, LoggerHandler):
    """MP SIEM Driver class to execute PDQL queries for MP SIEM."""

    _MPSIEM_REQD_ARGS = ["host", "username", "password"]

    def __init__(self, **kwargs):
        """Instantiate MPSEIM Driver."""
        super().__init__()
        self.service = None
        self._connected = False
        self.logger.setLevel(kwargs.get("log_level", "INFO"))
        self.set_driver_property(
            DriverProps.PUBLIC_ATTRS,
            {
                "client": self.service,
                "saved_searches": self._saved_searches,
                "fired_alerts": self._fired_alerts,
            },
        )
        self.set_driver_property(
            DriverProps.FORMATTERS,
            {"datetime": self._format_datetime, "list": self._format_list},
        )

        self.excluded_event_fields = [
            "_meta",
            "assets",
            "attacking_assets",
            "incident.aggregation.closed_behavior",
            "incident.aggregation.key",
            "incident.aggregation.time_window",
            "incident.aggregation.timeout",
            "incident.assigned_to_user_id",
            "incident.category",
            "incident.description",
            "incident.name",
            "incident.severity",
            "incident.severity_behavior",
            "subevents.time",
        ]

    def connect(self, connection_str: str = None, **kwargs):
        """
        Connect to MaxPatrol SIEM via mpsiemlib.

        Parameters
        ----------
        connection_str : Optional[str], optional
            Connection string

        Other Parameters
        ----------------
        kwargs :
            Connection parameters can be supplied as keyword parameters.

        Notes
        -----
        Default configuration is read from the DataProviders/MPSEIM
        section of msticpyconfig.yaml, if available.

        """

        cs_dict = self._get_connect_args(connection_str, **kwargs)

        arg_dict = {
            key: val for key, val in cs_dict.items() if key in MPSIEM_CONNECT_ARGS
        }
        try:
            log_level = kwargs.pop("loglevel", "INFO")
            self.logger.setLevel(log_level)
            auth_params = {
                "core": {
                    "hostname": arg_dict["host"],
                    "login": arg_dict["username"],
                    "pass": arg_dict["password"],
                    "auth_type": 0,
                },
                "siem": {"hostname": arg_dict["host"]},
                "storage": {"hostname": arg_dict["host"]},
            }
            auth = MPSIEMAuth(creds=Creds(auth_params), settings=Settings())
            self.service = EventsAPI(auth, Settings())
        except Exception as err:
            msg = f"Error connecting to MaxPatrol SIEM: {err}"
            self.logger.error(msg)
            raise MsticpyConnectionError(
                msg, title="MaxPatrol SIEM connection"
            ) from err

        self._connected = True
        self.logger.info("MaxPatrol SIEM driver connected to Core")

    def _get_connect_args(
        self, connection_str: Optional[str], **kwargs
    ) -> Dict[str, Any]:
        """Check and consolidate connection parameters."""
        cs_dict: Dict[str, Any] = {}
        # Fetch any config settings
        cs_dict.update(self._get_config_settings())
        # If a connection string - parse this and add to config
        if connection_str:
            cs_items = connection_str.split(";")
            cs_dict.update(
                {
                    cs_item.split("=")[0].strip(): cs_item.split("=")[1]
                    for cs_item in cs_items
                }
            )
        elif kwargs:
            # if connection args supplied as kwargs
            cs_dict.update(kwargs)
            check_kwargs(cs_dict, list(MPSIEM_CONNECT_ARGS.keys()))

        missing_args = set(self._MPSIEM_REQD_ARGS) - cs_dict.keys()
        if missing_args:
            msg = (
                "One or more mandatory connection parameters missing for MaxPatrol SIEM"
                + " "
                + ", ".join(missing_args)
                + f"Required parameters are: {', '.join(self._MPSIEM_REQD_ARGS)}"
                + "All parameters: "
                + ", ".join(
                    [f"{arg}: {desc}" for arg, desc in MPSIEM_CONNECT_ARGS.items()]
                )
            )

            self.logger.error(msg)

            raise MsticpyUserConfigError(
                msg, title="Have no MPSIEM connection parameters"
            )
        return cs_dict

    def query(
        self, query: str, query_source: QuerySource = None, **kwargs
    ) -> Union[pd.DataFrame, Any]:
        """
        Execute PDQL query and retrieve results.

        Parameters
        ----------
        query : str
            PDQL query to execute via API
        query_source : QuerySource
            The query definition object

        Other Parameters
        ----------------
        kwargs :
            Are passed to mpsiemlib
            count=0 by default

        Returns
        -------
        Union[pd.DataFrame, Any]
            Query results in a dataframe.
            or query response if an error.

        """
        del query_source
        if not self._connected:
            raise self._create_not_connected_err()

        count = kwargs.pop("count", 500)

        # TODO: Implement recursive in mpsiemlib
        recursive = kwargs.pop("recursive", False)

        default_start_dt = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        start = kwargs.pop(
            "time_start", calendar.timegm(default_start_dt.utctimetuple())
        )
        end = kwargs.pop("time_end", None)

        self.logger.debug(
            "MPSIEM query with parameters: "
            + f"filter: {query}, count: {count}, recursive: {recursive}, "
            + f"time_start: {start}, time_end: {end}"
        )

        fields = [
            f["name"]
            for f in self.service.get_events_metadata()
            if f["name"] not in self.excluded_event_fields
        ]
        reader = self.service.get_events_by_filter(
            filter=query,
            fields=fields,
            time_from=start,
            time_to=end,
            limit=count,
            offset=0,
        )

        resp_rows = pd.DataFrame()
        for row in reader:
            resp_rows = pd.concat([json_normalize(row), resp_rows.loc[:]]).reset_index(
                drop=True
            )
        if resp_rows.empty:
            self.logger.warning("Warning: query did not return any results.")
            return pd.DataFrame()
        return resp_rows

    def query_with_results(self, query: str, **kwargs) -> Tuple[pd.DataFrame, Any]:
        """
        Execute query string and return DataFrame of results.

        Parameters
        ----------
        query : str
            Query to execute against mpsiem instance.

        Returns
        -------
        Union[pd.DataFrame,Any]
            A DataFrame (if successful) or
            the underlying provider result if an error occurs.

        """
        pass

    @property
    def service_queries(self) -> Tuple[Dict[str, str], str]:
        """
        Return dynamic queries available on connection to service.

        Returns
        -------
        Tuple[Dict[str, str], str]
            Dictionary of query_name, query_text.
            Name of container to add queries to.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        if hasattr(self.service, "saved_searches") and self.service.saved_searches:
            queries = {
                search.name.strip().replace(" ", "_"): f"search {search['search']}"
                for search in self.service.saved_searches
            }
            return queries, "SavedSearches"
        return {}, "SavedSearches"

    @property
    def driver_queries(self) -> Iterable[Dict[str, Any]]:
        """
        Return dynamic queries available on connection to service.

        Returns
        -------
        Iterable[Dict[str, Any]]
            List of queries with properties: "name", "query", "container"
            and (optionally) "description"

        Raises
        ------
        MsticpyNotConnectedError
            If called before driver is connected.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        if hasattr(self.service, "saved_searches") and self.service.saved_searches:
            return [
                {
                    "name": search.name.strip().replace(" ", "_"),
                    "query": f"search {search['search']}",
                    "query_paths": "SavedSearches",
                    "description": "",
                }
                for search in self.service.saved_searches
            ]
        return []

    @property
    def _saved_searches(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of saved searches in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of saved searches with name and query columns.

        """
        if self.connected:
            return self._get_saved_searches()
        return None

    def _get_saved_searches(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of saved searches in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of saved searches with name and query columns.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        savedsearches = self.service.saved_searches

        out_df = pd.DataFrame(columns=["name", "query"])

        namelist = []
        querylist = []
        for savedsearch in savedsearches:
            namelist.append(savedsearch.name.replace(" ", "_"))
            querylist.append(savedsearch["search"])
        out_df["name"] = namelist
        out_df["query"] = querylist

        return out_df

    @property
    def _fired_alerts(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of fired alerts in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of fired alerts with alert name and count columns.

        """
        if self.connected:
            return self._get_fired_alerts()
        return None

    def _get_fired_alerts(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of fired alerts in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of fired alerts with alert name and count columns.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        firedalerts = self.service.fired_alerts

        out_df = pd.DataFrame(columns=["name", "count"])

        alert_names = []
        alert_counts = []
        for alert in firedalerts:
            alert_names.append(alert.name)
            alert_counts.append(alert.count)
        out_df["name"] = alert_names
        out_df["count"] = alert_counts

        return out_df

    # Parameter Formatting methods
    @staticmethod
    def _format_datetime(date_time: datetime) -> str:
        """Return datetime-formatted string."""
        return f'"{date_time.isoformat(sep=" ")}"'

    @staticmethod
    def _format_list(param_list: Iterable[Any]) -> str:
        """Return formatted list parameter."""
        fmt_list = [f'"{item}"' for item in param_list]
        return ",".join(fmt_list)

    # Read values from configuration
    @staticmethod
    def _get_config_settings() -> Dict[Any, Any]:
        """Get config from msticpyconfig."""
        data_provs = get_provider_settings(config_section="DataProviders")
        mpsiem_settings: Optional[ProviderSettings] = data_provs.get("MPSIEM")
        return getattr(mpsiem_settings, "Args", {})

    @staticmethod
    def _create_not_connected_err():
        return MsticpyNotConnectedError(
            "Please run the connect() method before running this method.",
            title="not connected to MPSIEM.",
        )
