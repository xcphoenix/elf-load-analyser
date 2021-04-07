import React from 'react';

import { Panel } from 'rsuite';

import 'rsuite/lib/Popover/styles';
import './index.css';
import { ReportModelState } from '@/models/report';
import { BuilderJsxFromModel} from '@/data/RenderData';

const RenderData = (props: ReportModelState) => {
  let content = BuilderJsxFromModel(props);
  return (
    <Panel className={'render-data'} header={props.name}>
      {content}
    </Panel>
  );
};

export default RenderData;
