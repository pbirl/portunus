import PropTypes from 'prop-types';
import { observer } from 'mobx-react';
import Paper from '@material-ui/core/Paper';
import { makeStyles } from '@material-ui/core/styles';
import classNames from 'classnames';

import BackButton from '@@/components/BackButton';

const useStyles = makeStyles({
  root: {
    flexGrow: 1,
  },
});

const Page = ({ children, className: externClassName, ...props }) => {
  const classes = useStyles();

  return (
    <Paper className={classNames(classes.root, externClassName)} {...props}>
      <BackButton />
      {children}
    </Paper>
  );
};

Page.propTypes = {
  children: PropTypes.node.isRequired,
  className: PropTypes.string,
};

Page.defaultProps = {
  className: '',
};

export default observer(Page);
