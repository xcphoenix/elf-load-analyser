import React from 'react';

import { Table } from 'rsuite';

import 'rsuite/lib/Table/styles';
import './index.css';

const { Column, HeaderCell, Cell } = Table;

const TableRender = (props: { table: Array<any>, desc?: string }) => {
  let colNum = props.table.length;
  if (colNum < 1) {
    return <div>没有数据</div>;
  }
  let firstObj = props.table[0];
  let Columns = Object.keys(firstObj).map((key) =>
    <Column width={200} key={key}>
      <HeaderCell>{key}</HeaderCell>
      <Cell dataKey={key} />
    </Column>,
  );
  return (
    <div className={'table-render'}>
      <Table
        height={colNum > 10 ? 400 : undefined}
        autoHeight={colNum <= 10}
        data={props.table}
        bordered={true}
      >
        {Columns}
      </Table>
      {props.desc ? <small>{props.desc}</small> : <></>}
    </div>
  );
};

export default TableRender;
