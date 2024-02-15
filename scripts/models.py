from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class IssueData:
    id: str
    title: str
    severity: str
    url: str
    exploitMaturity: str
    description: Optional[str] = None
    identifiers: Optional[Any] = None
    credit: Optional[List[str]] = None
    semver: Optional[Any] = None
    publicationTime: Optional[str] = None
    disclosureTime: Optional[str] = None
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = None
    cvssDetails: Optional[List[Any]] = None
    language: Optional[str] = None
    patches: Optional[Any] = None
    nearestFixedInVersion: Optional[str] = None
    ignoreReasons: Optional[List[Any]] = None


@dataclass
class FixInfo:
    isUpgradable: bool
    isPinnable: bool
    isPatchable: bool
    isFixable: bool
    isPartiallyFixable: bool
    nearestFixedInVersion: str
    fixedIn: Optional[List[str]] = None


@dataclass
class AggregatedIssue:
    id: str
    issueType: str
    pkgName: str
    pkgVersions: List[str]
    issueData: IssueData
    isPatched: bool
    isIgnored: bool
    fixInfo: FixInfo
    introducedThrough: Optional[List[Any]] = None
    ignoreReasons: Optional[List[Any]] = None
    priorityScore: Optional[int] = None
    priority: Optional[Any] = None
